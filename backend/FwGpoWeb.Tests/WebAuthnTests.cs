using FwGpoWeb.Auth;
using FwGpoWeb.Auth.WebAuthn;
using WebAuthn.Net.Models.Protocol.Enums;
using WebAuthn.Net.Services.Serialization.Cose.Models.Enums;
using WebAuthn.Net.Storage.Credential.Models;
using Xunit;

namespace FwGpoWeb.Tests;

public class WebAuthnTests
{
    [Fact]
    public void UpnUserHandleRoundTrip()
    {
        var upn = "Admin@Corp.Local";
        var handle = WebAuthnCredentialSerializer.UpnToUserHandle(upn);
        Assert.True(handle.Length > 0 && handle.Length <= 64);
        Assert.Equal("admin@corp.local", WebAuthnCredentialSerializer.UserHandleToUpn(handle));
    }

    [Fact]
    public void Ec2CredentialSerializationRoundTrip()
    {
        var x = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32 };
        var y = new byte[] { 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63 };
        var cred = new UserCredentialRecord(
            WebAuthnCredentialSerializer.UpnToUserHandle("user@corp.local"),
            "rp.local",
            "My key",
            new CredentialRecord(
                PublicKeyCredentialType.PublicKey,
                new byte[] { 9, 8, 7, 6, 5, 4, 3, 2, 1, 0, 9, 8, 7, 6, 5, 4, 3, 2 },
                new CredentialPublicKeyRecord(CoseKeyType.EC2, CoseAlgorithm.ES256, null,
                    new CredentialPublicKeyEc2ParametersRecord(
                        (WebAuthn.Net.Services.Serialization.Cose.Models.Enums.EC2.CoseEc2EllipticCurve)1, x, y),
                    null),
                7,
                new[] { AuthenticatorTransport.Internal },
                true, true, false,
                new byte[] { 0xAA }, new byte[] { 0xBB }));

        var json = WebAuthnCredentialSerializer.ToJson(cred);
        var back = WebAuthnCredentialSerializer.FromJson(json);
        Assert.Equal("rp.local", back.RpId);
        Assert.Equal(7u, back.CredentialRecord.SignCount);
        Assert.True(back.CredentialRecord.UvInitialized);
        Assert.Equal(cred.CredentialRecord.Id, back.CredentialRecord.Id);
        Assert.NotNull(back.CredentialRecord.PublicKey.Ec2);
        Assert.Equal(x, back.CredentialRecord.PublicKey.Ec2!.X);
        Assert.Equal(y, back.CredentialRecord.PublicKey.Ec2!.Y);
    }

    [Fact]
    public void RsaCredentialSerializationRoundTrip()
    {
        var n = new byte[256];
        var e = new byte[] { 1, 0, 1 };
        for (int i = 0; i < n.Length; i++) n[i] = (byte)(i % 251);
        var cred = new UserCredentialRecord(
            WebAuthnCredentialSerializer.UpnToUserHandle("user@corp.local"),
            "rp.local",
            null,
            new CredentialRecord(
                PublicKeyCredentialType.PublicKey,
                new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 },
                new CredentialPublicKeyRecord(CoseKeyType.RSA, CoseAlgorithm.RS256,
                    new CredentialPublicKeyRsaParametersRecord(n, e), null, null),
                0,
                Array.Empty<AuthenticatorTransport>(),
                false, false, false, null, null));

        var back = WebAuthnCredentialSerializer.FromJson(WebAuthnCredentialSerializer.ToJson(cred));
        Assert.NotNull(back.CredentialRecord.PublicKey.Rsa);
        Assert.Equal(n, back.CredentialRecord.PublicKey.Rsa!.ModulusN);
        Assert.Equal(e, back.CredentialRecord.PublicKey.Rsa!.ExponentE);
    }
}
