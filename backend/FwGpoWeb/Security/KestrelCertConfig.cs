using System.Net;
using Microsoft.AspNetCore.Server.Kestrel.Core;

namespace FwGpoWeb.Security;

/// <summary>
/// Applies the self-hosted (Kestrel) HTTPS certificate from configuration.
///
/// Config keys (App section):
///   KestrelCert:Path          = PFX file (e.g. C:\ProgramData\FwGpoWeb\certs\app.pfx)
///   KestrelCert:PasswordFile  = file containing the PFX password (NEWLINE-trimmed).
///                               The password deliberately lives OUTSIDE the
///                               world-readable app settings (the data dir is
///                               ACL-restricted to the service identity).
///
/// When KestrelCert:Path is set, the KestrelUrl port is taken from App:KestrelUrl
/// and the app binds HTTPS with the PFX (no use of UseUrls for the certificate
/// binding, to avoid double-binding). When not set, App:KestrelUrl is used as-is
/// (plain HTTP for development).
/// </summary>
public static class KestrelCertConfig
{
    /// <summary>Reads (and trims) the PFX password from a file. Throws a descriptive error when missing.</summary>
    public static string LoadPassword(string passwordFile)
    {
        if (!File.Exists(passwordFile))
            throw new InvalidOperationException(
                $"Certificate password file not found: {passwordFile}");
        var pwd = File.ReadAllText(passwordFile).Trim();
        return pwd;
    }

    /// <summary>
    /// Applies the Kestrel binding. Returns the effective port.
    /// Testable without a running host: validation errors surface here.
    /// </summary>
    public static int Apply(WebApplicationBuilder builder, Microsoft.Extensions.Configuration.IConfigurationSection appCfg)
    {
        var certPath = appCfg["KestrelCert:Path"];
        var url = appCfg["KestrelUrl"] ?? "http://0.0.0.0:5000";

        if (string.IsNullOrWhiteSpace(certPath))
        {
            // No certificate configured — use the URL as-is (dev / plain HTTP).
            builder.WebHost.UseUrls(url);
            return ParsePort(url, isHttps: false);
        }

        if (!File.Exists(certPath))
            throw new InvalidOperationException($"Kestrel certificate not found: {certPath}");

        var password = string.Empty;
        var passFile = appCfg["KestrelCert:PasswordFile"];
        if (!string.IsNullOrWhiteSpace(passFile))
            password = LoadPassword(passFile);

        var isHttps = url.StartsWith("https://", StringComparison.OrdinalIgnoreCase);
        var port = ParsePort(url, isHttps: true);

        // Open the certificate NOW (fail fast with a clear error at startup
        // instead of a late binding failure when Kestrel starts listening).
        var cert = new System.Security.Cryptography.X509Certificates.X509Certificate2(certPath, password);

        builder.WebHost.ConfigureKestrel(options =>
        {
            options.ListenAnyIP(port, listenOptions =>
            {
                listenOptions.UseHttps(cert);
            });
        });
        return port;
    }

    internal static int ParsePort(string url, bool isHttps)
    {
        try
        {
            var u = new Uri(url);
            if (u.IsDefaultPort)
                return isHttps ? 443 : 80;
            return u.Port;
        }
        catch (UriFormatException)
        {
            throw new InvalidOperationException($"Invalid KestrelUrl: {url}");
        }
    }
}
