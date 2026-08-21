using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using WebAuthn.Net.Models.Protocol.Enums;
using WebAuthn.Net.Services.Serialization.Cose.Models.Enums;
using WebAuthn.Net.Services.Serialization.Cose.Models.Enums.EC2;
using WebAuthn.Net.Services.Serialization.Cose.Models.Enums.OKP;
using WebAuthn.Net.Storage.Credential.Models;

namespace FwGpoWeb.Auth.WebAuthn;

internal sealed class FidoPubKeyDto
{
    [JsonPropertyName("kty")] public int Kty { get; set; }
    [JsonPropertyName("alg")] public int Alg { get; set; }
    [JsonPropertyName("crv")] public int? Crv { get; set; }
    [JsonPropertyName("x")] public string? X { get; set; }
    [JsonPropertyName("y")] public string? Y { get; set; }
    [JsonPropertyName("n")] public string? N { get; set; }
    [JsonPropertyName("e")] public string? E { get; set; }
}

internal sealed class FidoCredDto
{
    [JsonPropertyName("userHandle")] public string UserHandle { get; set; } = "";
    [JsonPropertyName("rpId")] public string RpId { get; set; } = "";
    [JsonPropertyName("desc")] public string? Description { get; set; }
    [JsonPropertyName("type")] public int Type { get; set; }
    [JsonPropertyName("credId")] public string CredId { get; set; } = "";
    [JsonPropertyName("signCount")] public uint SignCount { get; set; }
    [JsonPropertyName("transports")] public string[] Transports { get; set; } = Array.Empty<string>();
    [JsonPropertyName("uv")] public bool Uv { get; set; }
    [JsonPropertyName("backupEligible")] public bool BackupEligible { get; set; }
    [JsonPropertyName("backupState")] public bool BackupState { get; set; }
    [JsonPropertyName("attObj")] public string? AttestationObject { get; set; }
    [JsonPropertyName("attCdj")] public string? AttestationClientDataJson { get; set; }
    [JsonPropertyName("pub")] public FidoPubKeyDto Pub { get; set; } = new();
}

/// <summary>
/// JSON (base64) serialization of WebAuthn.Net credential records for our
/// file-based store. Round-trip tested in FwGpoWeb.Tests.
/// </summary>
public static class WebAuthnCredentialSerializer
{
    private static readonly JsonSerializerOptions Opts = new() { DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull };

    public static string ToJson(UserCredentialRecord rec)
    {
        var d = new FidoCredDto
        {
            UserHandle = Convert.ToBase64String(rec.UserHandle),
            RpId = rec.RpId,
            Description = rec.Description,
            Type = (int)rec.CredentialRecord.Type,
            CredId = Convert.ToBase64String(rec.CredentialRecord.Id),
            SignCount = rec.CredentialRecord.SignCount,
            Transports = rec.CredentialRecord.Transports.Select(t => t.ToString().ToLowerInvariant()).ToArray(),
            Uv = rec.CredentialRecord.UvInitialized,
            BackupEligible = rec.CredentialRecord.BackupEligible,
            BackupState = rec.CredentialRecord.BackupState,
            AttestationObject = rec.CredentialRecord.AttestationObject is null ? null : Convert.ToBase64String(rec.CredentialRecord.AttestationObject),
            AttestationClientDataJson = rec.CredentialRecord.AttestationClientDataJSON is null ? null : Convert.ToBase64String(rec.CredentialRecord.AttestationClientDataJSON),
            Pub = PubToDto(rec.CredentialRecord.PublicKey)
        };
        return JsonSerializer.Serialize(d, Opts);
    }

    public static UserCredentialRecord FromJson(string json)
    {
        var d = JsonSerializer.Deserialize<FidoCredDto>(json, Opts)
                ?? throw new InvalidDataException("empty credential record");
        var pub = DtoToPub(d.Pub);
        var cred = new CredentialRecord(
            (PublicKeyCredentialType)d.Type,
            Convert.FromBase64String(d.CredId),
            pub,
            d.SignCount,
            d.Transports.Select(t => Enum.Parse<AuthenticatorTransport>(t, ignoreCase: true)).ToArray(),
            d.Uv,
            d.BackupEligible,
            d.BackupState,
            string.IsNullOrEmpty(d.AttestationObject) ? null : Convert.FromBase64String(d.AttestationObject),
            string.IsNullOrEmpty(d.AttestationClientDataJson) ? null : Convert.FromBase64String(d.AttestationClientDataJson));
        return new UserCredentialRecord(Convert.FromBase64String(d.UserHandle), d.RpId, d.Description, cred);
    }

    private static FidoPubKeyDto PubToDto(CredentialPublicKeyRecord p) => new()
    {
        Kty = (int)p.Kty,
        Alg = (int)p.Alg,
        Crv = p.Ec2 is null ? (p.Okp is null ? null : (int)p.Okp.Crv) : (int)p.Ec2.Crv,
        X = p.Ec2?.X is not null ? Convert.ToBase64String(p.Ec2.X) : (p.Okp?.X is not null ? Convert.ToBase64String(p.Okp.X) : null),
        Y = p.Ec2?.Y is not null ? Convert.ToBase64String(p.Ec2.Y) : null,
        N = p.Rsa?.ModulusN is not null ? Convert.ToBase64String(p.Rsa.ModulusN) : null,
        E = p.Rsa?.ExponentE is not null ? Convert.ToBase64String(p.Rsa.ExponentE) : null
    };

    private static CredentialPublicKeyRecord DtoToPub(FidoPubKeyDto d)
    {
        var kty = (CoseKeyType)d.Kty;
        var alg = (CoseAlgorithm)d.Alg;
        switch (kty)
        {
            case CoseKeyType.EC2:
                return new CredentialPublicKeyRecord(kty, alg, null,
                    new CredentialPublicKeyEc2ParametersRecord((CoseEc2EllipticCurve)d.Crv!,
                        Convert.FromBase64String(d.X!), Convert.FromBase64String(d.Y!)), null);
            case CoseKeyType.OKP:
                return new CredentialPublicKeyRecord(kty, alg, null, null,
                    new CredentialPublicKeyOkpParametersRecord((CoseOkpEllipticCurve)d.Crv!,
                        Convert.FromBase64String(d.X!)));
            case CoseKeyType.RSA:
                return new CredentialPublicKeyRecord(kty, alg,
                    new CredentialPublicKeyRsaParametersRecord(Convert.FromBase64String(d.N!), Convert.FromBase64String(d.E!)),
                    null, null);
            default:
                throw new InvalidDataException($"Unsupported COSE key type: {d.Kty}");
        }
    }

    public static byte[] UpnToUserHandle(string upn) => Encoding.UTF8.GetBytes("fwgpo:" + upn.ToLowerInvariant());
    public static string UserHandleToUpn(byte[] userHandle)
    {
        var s = Encoding.UTF8.GetString(userHandle);
        return s.StartsWith("fwgpo:", StringComparison.OrdinalIgnoreCase) ? s[6..] : s;
    }
}
