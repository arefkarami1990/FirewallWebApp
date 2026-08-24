using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using FwGpoWeb.Security;
using Microsoft.AspNetCore.Builder;
using Xunit;

namespace FwGpoWeb.Tests;

public class KestrelCertConfigTests : IDisposable
{
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "fwgpo-kestreltest-" + Guid.NewGuid().ToString("N"));
    public KestrelCertConfigTests() => Directory.CreateDirectory(_dir);
    public void Dispose() { try { Directory.Delete(_dir, true); } catch { } }

    private string WritePfx(string pwd = "s3cret")
    {
        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest("CN=fwgpo.test", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        req.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, true));
        var cert = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));
        var pfx = Path.Combine(_dir, "app.pfx");
        File.WriteAllBytes(pfx, cert.Export(X509ContentType.Pfx, pwd));
        return pfx;
    }

    private WebApplicationBuilder Builder(string[] cfg)
    {
        var b = WebApplication.CreateBuilder();
        foreach (var kv in cfg)
        {
            var i = kv.IndexOf('=');
            b.Configuration[kv[..i]] = kv[(i + 1)..];
        }
        return b;
    }

    [Fact]
    public void LoadPassword_Trims()
    {
        var f = Path.Combine(_dir, "p.txt");
        File.WriteAllText(f, "  abc123  \n");
        Assert.Equal("abc123", KestrelCertConfig.LoadPassword(f));
    }

    [Fact]
    public void LoadPassword_MissingFile_Throws()
    {
        var ex = Assert.Throws<InvalidOperationException>(
            () => KestrelCertConfig.LoadPassword(Path.Combine(_dir, "nope.txt")));
        Assert.Contains("password file not found", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Apply_NoCert_UsesUrlAsIs_ReturnsPort()
    {
        var b = Builder(new[] { "App:KestrelUrl=http://0.0.0.0:5000" });
        var port = KestrelCertConfig.Apply(b, b.Configuration.GetSection("App"));
        Assert.Equal(5000, port);
    }

    [Fact]
    public void Apply_CertPathMissing_Throws()
    {
        var b = Builder(new[]
        {
            "App:KestrelUrl=https://0.0.0.0:443",
            "App:KestrelCert:Path=" + Path.Combine(_dir, "missing.pfx"),
        });
        var ex = Assert.Throws<InvalidOperationException>(
            () => KestrelCertConfig.Apply(b, b.Configuration.GetSection("App")));
        Assert.Contains("certificate not found", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Apply_WithPfxAndPassword_Binds_ReturnsPort()
    {
        var pfx = WritePfx("pw1");
        var passFile = Path.Combine(_dir, "pass.txt");
        File.WriteAllText(passFile, "pw1\n");
        var b = Builder(new[]
        {
            "App:KestrelUrl=https://0.0.0.0:8443",
            "App:KestrelCert:Path=" + pfx,
            "App:KestrelCert:PasswordFile=" + passFile,
        });
        var port = KestrelCertConfig.Apply(b, b.Configuration.GetSection("App"));
        Assert.Equal(8443, port);
    }

    [Fact]
    public void Apply_PfxWrongPassword_Throws()
    {
        var pfx = WritePfx("realpw");
        var passFile = Path.Combine(_dir, "pass.txt");
        File.WriteAllText(passFile, "WRONG\n");
        var b = Builder(new[]
        {
            "App:KestrelUrl=https://0.0.0.0:8443",
            "App:KestrelCert:Path=" + pfx,
            "App:KestrelCert:PasswordFile=" + passFile,
        });
        // Wrong password surfaces when the PFX is opened during binding setup.
        Assert.ThrowsAny<Exception>(() => KestrelCertConfig.Apply(b, b.Configuration.GetSection("App")));
    }

    [Fact]
    public void Apply_PasswordFileMissing_Throws()
    {
        var pfx = WritePfx("pw");
        var b = Builder(new[]
        {
            "App:KestrelUrl=https://0.0.0.0:8443",
            "App:KestrelCert:Path=" + pfx,
            "App:KestrelCert:PasswordFile=" + Path.Combine(_dir, "nope.txt"),
        });
        var ex = Assert.Throws<InvalidOperationException>(
            () => KestrelCertConfig.Apply(b, b.Configuration.GetSection("App")));
        Assert.Contains("password file not found", ex.Message, StringComparison.OrdinalIgnoreCase);
    }
}
