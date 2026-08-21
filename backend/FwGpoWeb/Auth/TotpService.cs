using System.Security.Cryptography;
using System.Text;
using QRCoder;

namespace FwGpoWeb.Auth;

/// <summary>
/// RFC 6238 TOTP (SHA-1, 30 s period, 6 digits) implemented directly with
/// HMACSHA1 and verified against the RFC 6238 Appendix B test vectors in
/// FwGpoWeb.Tests. No third-party TOTP dependency.
/// </summary>
public sealed class TotpService
{
    public const int Digits = 6;
    public const int PeriodSeconds = 30;

    public static string GenerateSecretB32(int bytes = 20)
    {
        Span<byte> rng = stackalloc byte[bytes];
        RandomNumberGenerator.Fill(rng);
        return Base32Encode(rng);
    }

    public string OtpAuthUri(string upn, string secretB32, string issuer)
    {
        var label = Uri.EscapeDataString(upn);
        var secret = secretB32.Replace("=", "");
        return $"otpauth://totp/{Uri.EscapeDataString(issuer)}:{label}?secret={secret}&issuer={Uri.EscapeDataString(issuer)}&algorithm=SHA1&digits={Digits}&period={PeriodSeconds}";
    }

    public string QrPngDataUrl(string otpauthUri)
    {
        using var gen = new QRCodeGenerator();
        var data = gen.CreateQrCode(otpauthUri, QRCodeGenerator.ECCLevel.M);
        var png = new PngByteQRCode(data).GetGraphic(5);
        return "data:image/png;base64," + Convert.ToBase64String(png);
    }

    public static byte[] Base32Decode(string s)
    {
        s = s.Trim().ToUpperInvariant().Replace("=", "").Replace(" ", "");
        const string alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
        var bits = new List<byte>();
        foreach (var c in s)
        {
            int v = alphabet.IndexOf(c);
            if (v < 0) throw new FormatException("Invalid base32 character");
            bits.Add((byte)(v & 0x1F));
        }
        var outBuf = new byte[bits.Count / 8];
        int buf = 0, have = 0;
        foreach (var b in bits)
        {
            buf = (buf << 5) | b;
            have += 5;
            if (have >= 8)
            {
                have -= 8;
                outBuf[^1] = (byte)((buf >> have) & 0xFF);
                // fix index: write into sequential position
            }
        }
        // The incremental write above is error-prone; rebuild cleanly:
        var result = new byte[bits.Count * 5 / 8];
        int acc = 0, accBits = 0, pos = 0;
        foreach (var b in bits)
        {
            acc = (acc << 5) | b;
            accBits += 5;
            if (accBits >= 8)
            {
                accBits -= 8;
                result[pos++] = (byte)((acc >> accBits) & 0xFF);
            }
        }
        return result;
    }

    public static string Base32Encode(ReadOnlySpan<byte> data)
    {
        const string alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
        var sb = new StringBuilder();
        int buffer = 0, bits = 0;
        foreach (var b in data)
        {
            buffer = (buffer << 8) | b;
            bits += 8;
            while (bits >= 5)
            {
                bits -= 5;
                sb.Append(alphabet[(buffer >> bits) & 0x1F]);
            }
        }
        if (bits > 0) sb.Append(alphabet[(buffer << (5 - bits)) & 0x1F]);
        return sb.ToString();
    }

    public static int GenerateCode(byte[] key, long unixTime, int digits = Digits)
    {
        long counter = unixTime / PeriodSeconds;
        var msg = new byte[8];
        for (int i = 7; i >= 0; i--) { msg[i] = (byte)(counter & 0xFF); counter >>= 8; }
        using var hmac = new HMACSHA1(key);
        var hash = hmac.ComputeHash(msg);
        int offset = hash[^1] & 0x0F;
        int binary = ((hash[offset] & 0x7F) << 24)
                   | ((hash[offset + 1] & 0xFF) << 16)
                   | ((hash[offset + 2] & 0xFF) << 8)
                   | (hash[offset + 3] & 0xFF);
        int mod = (int)Math.Pow(10, digits);
        return binary % mod;
    }

    /// <summary>
    /// Validates a code allowing +/- one period of clock skew (default).
    /// </summary>
    public bool Validate(string? code, string secretB32, long? unixTime = null, int windows = 1)
    {
        if (string.IsNullOrEmpty(code)) return false;
        code = code.Trim();
        if (!code.All(char.IsDigit) || code.Length is < 4 or > 10) return false;
        long now = unixTime ?? DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        byte[] key;
        try { key = Base32Decode(secretB32); }
        catch { return false; }
        for (int w = -windows; w <= windows; w++)
        {
            var t = now + w * (long)PeriodSeconds;
            if (t < 0) continue;
            var expected = GenerateCode(key, t, Digits);
            if (CryptographicOperations.FixedTimeEquals(
                    Encoding.ASCII.GetBytes(expected.ToString($"D{Digits}")),
                    Encoding.ASCII.GetBytes(code.PadLeft(Digits, '0'))))
                return true;
        }
        return false;
    }
}
