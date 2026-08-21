using System.Text;
using System.Text.RegularExpressions;
using FwGpoWeb.Models;

namespace FwGpoWeb.Security;

/// <summary>
/// Defense-in-depth input validation. Mirrors the PowerShell layer's rules
/// (FwGpoBuilder.psm1) so malicious values are rejected BEFORE they ever
/// reach the PowerShell process. The PowerShell layer re-validates everything.
/// </summary>
public static partial class InputValidator
{
    private static readonly string[] FwKeywords =
        { "Any", "LocalSubnet", "DNS", "DHCP", "WINS", "DefaultGateway", "Internet", "PlayToDevice" };

    [GeneratedRegex(@"^\d{1,3}(\.\d{1,3}){3}$")]
    private static partial Regex IpRegex();

    [GeneratedRegex(@"^(\d{1,3}(?:\.\d{1,3}){3})/(\d{1,2})$")]
    private static partial Regex CidrRegex();

    [GeneratedRegex(@"^(\d{1,3}(?:\.\d{1,3}){3})/(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$")]
    private static partial Regex DottedMaskRegex();

    [GeneratedRegex(@"^(\d{1,3}(?:\.\d{1,3}){3})-(\d{1,3}(?:\.\d{1,3}){3})$")]
    private static partial Regex IpRangeRegex();

    public static bool IsValidIp(string? ip)
    {
        if (string.IsNullOrWhiteSpace(ip)) return false;
        ip = new string(ip.Where(c => char.IsDigit(c) || c == '.').ToArray());
        if (!IpRegex().IsMatch(ip)) return false;
        foreach (var p in ip.Split('.'))
        {
            if (!int.TryParse(p, out var n) || n < 0 || n > 255) return false;
        }
        return true;
    }

    public static int? SubnetMaskToPrefix(string mask)
    {
        if (!IsValidIp(mask)) return null;
        uint ip = IpToUint32(mask);
        if (ip == 0) return 0;
        if (ip == uint.MaxValue) return 32;
        uint inv = uint.MaxValue - ip;
        if ((inv & (inv + 1)) != 0) return null;
        int count = 0;
        for (int i = 31; i >= 0; i--)
        {
            if (((ip >> i) & 1) == 1) count++; else break;
        }
        return count;
    }

    public static uint IpToUint32(string ip)
    {
        var bytes = System.Net.IPAddress.Parse(ip).GetAddressBytes();
        return (uint)((bytes[0] << 24) | (bytes[1] << 16) | (bytes[2] << 8) | bytes[3]);
    }

    public static bool IsIpOrCidr(string? s)
    {
        if (string.IsNullOrWhiteSpace(s)) return false;
        s = new string(s.Trim().Where(c => char.IsDigit(c) || c is '.' or '/' or '-').ToArray());
        if (FwKeywords.Contains(s)) return true;
        var m = CidrRegex().Match(s);
        if (m.Success)
        {
            if (!IsValidIp(m.Groups[1].Value)) return false;
            return int.TryParse(m.Groups[2].Value, out var p) && p is >= 0 and <= 32;
        }
        m = DottedMaskRegex().Match(s);
        if (m.Success)
        {
            if (!IsValidIp(m.Groups[1].Value)) return false;
            return SubnetMaskToPrefix(m.Groups[2].Value) is not null;
        }
        m = IpRangeRegex().Match(s);
        if (m.Success) return IsValidIp(m.Groups[1].Value) && IsValidIp(m.Groups[2].Value);
        return IsValidIp(s);
    }

    public sealed record ParsedAddressList(string[] Valid, string[] Invalid);

    /// <summary>
    /// Tokenizes the user's IP list the same way the PowerShell layer does:
    /// split on comma/whitespace/semicolon, strip to [0-9./-A-Za-z], validate
    /// each token. Only pure IP/CIDR/range tokens can ever pass.
    /// </summary>
    public static ParsedAddressList ParseAddressList(string? text)
    {
        var valid = new List<string>();
        var invalid = new List<string>();
        if (string.IsNullOrWhiteSpace(text)) return new(valid.ToArray(), invalid.ToArray());
        foreach (var rawLine in text.Split('\n', '\r'))
        {
            var line = rawLine.Trim();
            if (line.Length == 0) continue;
            foreach (var seg in line.Split(new[] { ' ', ',', ';' }, StringSplitOptions.RemoveEmptyEntries))
            {
                var cleaned = new string(seg.Trim().Where(c => char.IsLetterOrDigit(c) || c is '.' or '/' or '-').ToArray());
                if (cleaned.Length == 0) continue;
                if (IsIpOrCidr(cleaned)) valid.Add(cleaned);
                else invalid.Add(cleaned);
            }
        }
        return new(valid.ToArray(), invalid.ToArray());
    }

    public static bool TryParsePort(string? text, out int port, out bool portIsAny)
    {
        port = 0; portIsAny = false;
        if (string.IsNullOrWhiteSpace(text)) return false;
        var t = text.Trim();
        if (t is "Any" or "any" or "*") { portIsAny = true; return true; }
        if (!int.TryParse(t, out port)) return false;
        return port is >= 1 and <= 65535;
    }

    public static bool IsValidProtocol(string? p) => p is "TCP" or "UDP" or "Any";
    public static bool IsValidMode(string? m) => m is "specific" or "any" or "localsubnet";

    /// <summary>
    /// Loose but strict-enough DN validation: rejects shell metacharacters,
    /// control chars and absurd lengths before the value reaches AD.
    /// </summary>
    public static bool IsValidDn(string? dn)
    {
        if (string.IsNullOrWhiteSpace(dn)) return false;
        if (dn.Length > 1000) return false;
        foreach (var c in dn)
        {
            if (char.IsControl(c)) return false;
            // shell metacharacters that could be abused if ever embedded in a
            // command line or path: | & ` $ ; * ? newline are all rejected
            if (c is '|' or '&' or '`' or '$' or ';' or '*' or '?' or '"' or '\'') return false;
        }
        var t = dn.TrimStart();
        if (!t.StartsWith("OU=", StringComparison.OrdinalIgnoreCase) &&
            !t.StartsWith("CN=", StringComparison.OrdinalIgnoreCase) &&
            !t.StartsWith("DC=", StringComparison.OrdinalIgnoreCase))
            return false;
        return dn.Contains(',');
    }

    public static string SanitizeGpoName(string s)
    {
        var sb = new StringBuilder(s.Length);
        foreach (var c in s)
            sb.Append(c is '\\' or '/' or ':' or '*' or '?' or '"' or '<' or '>' or '|' ? '_' : c);
        return sb.ToString();
    }

    public static bool IsValidJsonSafe(string? s) => !string.IsNullOrWhiteSpace(s) && s.Length <= 2000;
}
