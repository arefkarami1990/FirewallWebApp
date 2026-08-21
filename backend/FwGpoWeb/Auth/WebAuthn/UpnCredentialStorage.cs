using WebAuthn.Net.Models.Protocol;
using WebAuthn.Net.Storage.Credential;
using WebAuthn.Net.Storage.Credential.Models;
using FwGpoWeb.Auth;

namespace FwGpoWeb.Auth.WebAuthn;

/// <summary>
/// Credential storage backed by the encrypted per-user secret store.
/// userHandle encodes the UPN so that a credential is always scoped to the
/// authenticated user it was registered for.
/// </summary>
public sealed class UpnCredentialStorage : ICredentialStorage<UpnWebAuthnContext>
{
    private readonly UserSecretStore _store;

    public UpnCredentialStorage(UserSecretStore store) => _store = store;

    public async Task<PublicKeyCredentialDescriptor[]> FindDescriptorsAsync(
        UpnWebAuthnContext context, string rpId, byte[] userHandle, CancellationToken cancellationToken)
    {
        var secrets = await _store.LoadAsync(context.Upn);
        var result = new List<PublicKeyCredentialDescriptor>();
        foreach (var f in secrets.Fido)
        {
            try
            {
                var rec = WebAuthnCredentialSerializer.FromJson(f.RecordB64);
                if (rec.RpId != rpId) continue;
                result.Add(new PublicKeyCredentialDescriptor(
                    rec.CredentialRecord.Type,
                    rec.CredentialRecord.Id,
                    rec.CredentialRecord.Transports.Length > 0 ? rec.CredentialRecord.Transports : null));
            }
            catch { /* skip corrupt record */ }
        }
        return result.ToArray();
    }

    public async Task<UserCredentialRecord?> FindExistingCredentialForAuthenticationAsync(
        UpnWebAuthnContext context, string rpId, byte[] userHandle, byte[] credentialId, CancellationToken cancellationToken)
    {
        var wantedId = Convert.ToBase64String(credentialId);
        var secrets = await _store.LoadAsync(context.Upn);
        foreach (var f in secrets.Fido)
        {
            if (f.CredIdB64 != wantedId) continue;
            try
            {
                var rec = WebAuthnCredentialSerializer.FromJson(f.RecordB64);
                return rec.RpId == rpId ? rec : null;
            }
            catch { return null; }
        }
        return null;
    }

    public async Task<bool> SaveIfNotRegisteredForOtherUserAsync(
        UpnWebAuthnContext context, UserCredentialRecord credential, CancellationToken cancellationToken)
    {
        var owner = await _store.FindCredentialOwnerAsync(credential.RpId, Convert.ToBase64String(credential.CredentialRecord.Id));
        if (owner is not null && !string.Equals(owner, context.Upn, StringComparison.OrdinalIgnoreCase))
            return false; // credential already registered for a different user
        await SaveCredentialAsync(context, credential);
        return true;
    }

    public async Task<bool> UpdateCredentialAsync(
        UpnWebAuthnContext context, UserCredentialRecord credential, CancellationToken cancellationToken)
    {
        var secrets = await _store.LoadAsync(context.Upn);
        var credId = Convert.ToBase64String(credential.CredentialRecord.Id);
        var existing = secrets.Fido.FirstOrDefault(f => f.CredIdB64 == credId);
        if (existing is null) return false;
        try
        {
            var rec = WebAuthnCredentialSerializer.FromJson(existing.RecordB64);
            if (rec.RpId != credential.RpId) return false;
        }
        catch { return false; }
        existing.RecordB64 = WebAuthnCredentialSerializer.ToJson(credential);
        await _store.SaveAsync(context.Upn, secrets);
        return true;
    }

    public async Task SaveCredentialAsync(UpnWebAuthnContext context, UserCredentialRecord credential)
    {
        var secrets = await _store.LoadAsync(context.Upn);
        var json = WebAuthnCredentialSerializer.ToJson(credential);
        var credId = Convert.ToBase64String(credential.CredentialRecord.Id);
        var existing = secrets.Fido.FirstOrDefault(f => f.CredIdB64 == credId);
        if (existing is null)
        {
            secrets.Fido.Add(new FidoCredentialRecord
            {
                CredIdB64 = credId,
                Description = credential.Description,
                CreatedAt = DateTimeOffset.UtcNow,
                RecordB64 = json
            });
        }
        else
        {
            existing.RecordB64 = json;
            existing.Description = credential.Description;
        }
        await _store.SaveAsync(context.Upn, secrets);
    }
}
