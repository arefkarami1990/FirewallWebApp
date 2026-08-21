using System.Security.Cryptography;
using System.Security.Cryptography;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace FwGpoWeb.Auth;

public sealed class TotpSecret
{
    [JsonPropertyName("secretB32")] public string SecretB32 { get; set; } = "";
    [JsonPropertyName("createdAt")] public DateTimeOffset CreatedAt { get; set; }
}

public sealed class FidoCredentialRecord
{
    [JsonPropertyName("credId")] public string CredIdB64 { get; set; } = "";
    [JsonPropertyName("desc")] public string? Description { get; set; }
    [JsonPropertyName("createdAt")] public DateTimeOffset CreatedAt { get; set; }
    // Binary credential record serialized by the WebAuthn layer (base64)
    [JsonPropertyName("recordB64")] public string RecordB64 { get; set; } = "";
}

public sealed class UserSecrets
{
    [JsonPropertyName("totp")] public TotpSecret? Totp { get; set; }
    [JsonPropertyName("fido")] public List<FidoCredentialRecord> Fido { get; set; } = new();
    [JsonPropertyName("version")] public int Version { get; set; } = 1;
}

/// <summary>
/// Persistent per-user secret store (TOTP secret + FIDO2 credentials).
/// The whole JSON document is encrypted at rest:
///   - Windows: DPAPI (machine scope)
///   - Non-Windows (dev/test): AES-256-GCM envelope (dev fallback, not for prod)
/// Access is additionally restricted by filesystem ACLs (set by the installer).
/// </summary>
public sealed class UserSecretStore
{
    private static readonly JsonSerializerOptions JsonOpts = new()
    {
        WriteIndented = true,
        DefaultIgnoreCondition = JsonIgnoreCondition.Never
    };

    private readonly string _dir;
    private readonly string _file;
    private readonly SemaphoreSlim _gate = new(1, 1);

    public UserSecretStore(string dataDir)
    {
        _dir = Path.Combine(dataDir, "secrets");
        Directory.CreateDirectory(_dir);
        _file = Path.Combine(_dir, "users.json.enc");
        ApplyAcls();
    }

    private void ApplyAcls()
    {
        if (!OperatingSystem.IsWindows()) return;
        try
        {
            var sd = new DirectorySecurity();
            sd.AddAccessRule(new FileSystemAccessRule(
                new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null).ToString(),
                FileSystemRights.FullControl, AccessControlType.Allow));
            sd.AddAccessRule(new FileSystemAccessRule(
                new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null).ToString(),
                FileSystemRights.FullControl, AccessControlType.Allow));
            new DirectoryInfo(_dir).SetAccessControl(sd);
        }
        catch { /* best effort */ }
    }

    public async Task<UserSecrets> LoadAsync(string upn)
    {
        await _gate.WaitAsync();
        try
        {
            var all = await LoadAllAsync();
            return all.TryGetValue(upn, out var s) ? s : new UserSecrets();
        }
        finally { _gate.Release(); }
    }

    public async Task SaveAsync(string upn, UserSecrets secrets)
    {
        await _gate.WaitAsync();
        try
        {
            var all = await LoadAllAsync();
            all[upn] = secrets;
            var json = JsonSerializer.Serialize(all, JsonOpts);
            var plain = System.Text.Encoding.UTF8.GetBytes(json);
            var enc = Protect(plain);
            await File.WriteAllBytesAsync(_file, enc);
        }
        finally { _gate.Release(); }
    }

    public async Task DeleteFidoCredentialAsync(string upn, string credIdB64)
    {
        var s = await LoadAsync(upn);
        s.Fido.RemoveAll(f => f.CredIdB64 == credIdB64);
        await SaveAsync(upn, s);
    }

    /// <summary>
    /// Returns the UPN that owns the given credential (rpId + credentialId),
    /// or null. Used by WebAuthn storage to prevent cross-user credential reuse.
    /// </summary>
    public async Task<string?> FindCredentialOwnerAsync(string rpId, string credIdB64)
    {
        await _gate.WaitAsync();
        try
        {
            var all = await LoadAllAsync();
            foreach (var (upn, s) in all)
            {
                foreach (var f in s.Fido)
                {
                    if (f.CredIdB64 != credIdB64) continue;
                    try
                    {
                        var rec = WebAuthn.WebAuthnCredentialSerializer.FromJson(f.RecordB64);
                        if (rec.RpId == rpId) return upn;
                    }
                    catch { /* corrupt */ }
                }
            }
            return null;
        }
        finally { _gate.Release(); }
    }

    private async Task<Dictionary<string, UserSecrets>> LoadAllAsync()
    {
        if (!File.Exists(_file)) return new Dictionary<string, UserSecrets>();
        var enc = await File.ReadAllBytesAsync(_file);
        var plain = Unprotect(enc);
        var dict = JsonSerializer.Deserialize<Dictionary<string, UserSecrets>>(plain, JsonOpts);
        return dict ?? new Dictionary<string, UserSecrets>();
    }

    // ----- protection -----

    private byte[] Protect(byte[] plain)
    {
        if (OperatingSystem.IsWindows())
        {
            return ProtectedData.Protect(plain, null, DataProtectionScope.LocalMachine);
        }
        // Dev fallback: AES-256-GCM with a key stored beside the data.
        var keyFile = _dir + "/.devkey";
        byte[] key;
        if (File.Exists(keyFile)) key = File.ReadAllBytes(keyFile);
        else { key = new byte[32]; RandomNumberGenerator.Fill(key); File.WriteAllBytes(keyFile, key); }
        var iv = new byte[12];
        RandomNumberGenerator.Fill(iv);
        var ct = new byte[plain.Length];
        var tag = new byte[16];
        using var aes = new AesGcm(key, 16);
        aes.Encrypt(iv, plain, ct, tag);
        return iv.Concat(tag).Concat(ct).ToArray();
    }

    private byte[] Unprotect(byte[] enc)
    {
        if (OperatingSystem.IsWindows())
        {
            return ProtectedData.Unprotect(enc, null, DataProtectionScope.LocalMachine);
        }
        var keyFile = _dir + "/.devkey";
        var key = File.ReadAllBytes(keyFile);
        var iv = enc.AsSpan(0, 12).ToArray();
        var tag = enc.AsSpan(12, 16).ToArray();
        var ct = enc.AsSpan(28).ToArray();
        var pt = new byte[ct.Length];
        using var aes = new AesGcm(key, 16);
        aes.Decrypt(iv, ct, tag, pt);
        return pt;
    }
}
