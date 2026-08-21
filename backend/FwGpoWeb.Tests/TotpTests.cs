using FwGpoWeb.Auth;
using Xunit;

namespace FwGpoWeb.Tests;

public class TotpTests
{
    // RFC 6238 Appendix B - SHA-1 test vectors (8 digits). We compute with
    // digits=8 and compare, then separately verify 6-digit behaviour.
    private static readonly (long Time, string Code)[] Vectors =
    {
        (59, "94287082"),
        (1111111109, "07081804"),
        (1111111111, "14050471"),
        (1234567890, "89005924"),
        (2000000000, "69279037"),
        (20000000000, "65353130"),
    };

    [Fact]
    public void Rfc6238Sha1Vectors()
    {
        var key = System.Text.Encoding.ASCII.GetBytes("12345678901234567890");
        foreach (var (time, code) in Vectors)
        {
            var got = TotpService.GenerateCode(key, time, digits: 8);
            Assert.Equal(code, got.ToString("D8"));
        }
    }

    [Fact]
    public void Base32RoundTrip()
    {
        var data = new byte[] { 0x00, 0x01, 0x02, 0xFF, 0xAB, 0xCD };
        var enc = TotpService.Base32Encode(data);
        var dec = TotpService.Base32Decode(enc);
        Assert.Equal(data, dec.Take(data.Length).ToArray());
    }

    [Fact]
    public void ValidateAcceptsCurrentCodeAndRejectsGarbage()
    {
        var svc = new TotpService();
        var secret = TotpService.GenerateSecretB32();
        var key = TotpService.Base32Decode(secret);
        long now = 1_700_000_000L;
        var code = TotpService.GenerateCode(key, now, 6).ToString("D6");

        Assert.True(svc.Validate(code, secret, unixTime: now));
        Assert.True(svc.Validate(code, secret, unixTime: now + 30));      // +1 window
        Assert.True(svc.Validate(code, secret, unixTime: now - 30));      // -1 window
        Assert.False(svc.Validate("000000", secret, unixTime: now + 600));
        Assert.False(svc.Validate("", secret, unixTime: now));
        Assert.False(svc.Validate("abcdef", secret, unixTime: now));
        Assert.False(svc.Validate(code, "not-base32!!!", unixTime: now));
    }

    [Fact]
    public void OtpAuthUriHasExpectedShape()
    {
        var svc = new TotpService();
        var uri = svc.OtpAuthUri("user@corp.local", "JBSWY3DPEHPK3PXP", "FWGPO");
        Assert.StartsWith("otpauth://totp/", uri);
        Assert.Contains("secret=JBSWY3DPEHPK3PXP", uri);
        Assert.Contains("digits=6", uri);
        Assert.Contains("period=30", uri);
    }
}
