using FwGpoWeb.Security;
using Xunit;

namespace FwGpoWeb.Tests;

public class InputValidatorTests
{
    [Theory]
    [InlineData("10.0.0.1", true)]
    [InlineData("0.0.0.0", true)]
    [InlineData("255.255.255.255", true)]
    [InlineData("256.1.1.1", false)]
    [InlineData("1.2.3", false)]
    [InlineData("", false)]
    [InlineData("1.2.3.4.5", false)]
    [InlineData("abc", false)]
    public void IsValidIp(string ip, bool expected) => Assert.Equal(expected, InputValidator.IsValidIp(ip));

    [Theory]
    [InlineData("10.0.0.0/24", true)]
    [InlineData("10.0.0.0/32", true)]
    [InlineData("10.0.0.0/0", true)]
    [InlineData("10.0.0.0/33", false)]
    [InlineData("10.0.0.1-10.0.0.9", true)]
    [InlineData("10.0.0.0/255.255.255.0", true)]
    [InlineData("10.0.0.0/255.255.255.128", true)]
    [InlineData("10.0.0.0/255.0.255.0", false)]
    [InlineData("garbage", false)]
    [InlineData("", false)]
    public void IsIpOrCidr(string s, bool expected) => Assert.Equal(expected, InputValidator.IsIpOrCidr(s));

    [Theory]
    [InlineData("255.255.255.0", 24)]
    [InlineData("255.255.0.0", 16)]
    [InlineData("255.0.0.0", 8)]
    [InlineData("255.255.255.128", 25)]
    [InlineData("255.192.0.0", 10)]
    [InlineData("255.128.0.0", 9)]
    [InlineData("0.0.0.0", 0)]
    [InlineData("255.255.255.255", 32)]
    [InlineData("255.0.255.0", null)]
    [InlineData("255.255.254.255", null)]
    public void SubnetMaskToPrefix(string mask, int? expected) => Assert.Equal(expected, InputValidator.SubnetMaskToPrefix(mask));

    [Fact]
    public void ParseAddressListInjectionSafe()
    {
        var (valid, invalid) = InputValidator.ParseAddressList("1.2.3.4; rm -rf /");
        Assert.Contains("1.2.3.4", valid);
        Assert.DoesNotContain(valid, v => v.Contains(' ') || v.Contains('-') && v != "" && v.Length > 1 && !v.All(c => char.IsDigit(c) || c is '.' or '/' or '-'));
        Assert.DoesNotContain("rm", valid);
        Assert.DoesNotContain("-rf", valid);
    }

    [Fact]
    public void ParseAddressListMixed()
    {
        var (valid, invalid) = InputValidator.ParseAddressList("10.0.0.1, 10.0.0.0/24;10.0.1.1-10.0.1.9\ngarbage 10.2.0.0/255.255.0.0");
        Assert.Equal(4, valid.Length);
        Assert.Contains("10.0.0.1", valid);
        Assert.Contains("10.0.0.0/24", valid);
        Assert.Contains("10.0.1.1-10.0.1.9", valid);
        Assert.Contains("10.2.0.0/255.255.0.0", valid);
        Assert.Single(invalid);
        Assert.Equal("garbage", invalid[0]);
    }

    [Theory]
    [InlineData("3389", 3389, false)]
    [InlineData("Any", 0, true)]
    [InlineData("*", 0, true)]
    [InlineData("0", 0, false)]
    [InlineData("70000", 0, false)]
    [InlineData("", 0, false)]
    public void TryParsePort(string s, int port, bool any)
    {
        var ok = InputValidator.TryParsePort(s, out var p, out var a);
        if (port > 0 || any) Assert.True(ok);
        Assert.Equal(any, a);
        if (port > 0) Assert.Equal(port, p);
    }

    [Theory]
    [InlineData("OU=Servers,DC=corp,DC=local", true)]
    [InlineData("OU=Servers,DC=corp,DC=local|whoami", false)]
    [InlineData("OU=Servers,DC=corp,DC=local & rm", false)]
    [InlineData("C:\\Windows", false)]
    [InlineData("", false)]
    [InlineData("OU=X,DC=a,DC=b$(whoami)", false)]
    public void IsValidDn(string dn, bool expected) => Assert.Equal(expected, InputValidator.IsValidDn(dn));

    [Fact]
    public void IpUint32RoundTrip()
    {
        foreach (var ip in new[] { "0.0.0.0", "1.2.3.4", "10.0.0.1", "192.168.1.1", "255.255.255.255" })
        {
            var u = InputValidator.IpToUint32(ip);
            var bytes = new[] { (byte)(u >> 24), (byte)(u >> 16), (byte)(u >> 8), (byte)u };
            Assert.Equal(ip, $"{bytes[0]}.{bytes[1]}.{bytes[2]}.{bytes[3]}");
        }
    }

    [Fact]
    public void SanitizeGpoNameStripsIllegal()
    {
        // every illegal char becomes one underscore (so ?" -> two underscores)
        Assert.Equal("a_b_c_d__e_f_g_h", InputValidator.SanitizeGpoName("a/b:c*d?\"e<f>g|h"));
        Assert.Equal("Servers-Access-3389-TCP-ADD", InputValidator.SanitizeGpoName("Servers-Access-3389-TCP-ADD"));
    }
}
