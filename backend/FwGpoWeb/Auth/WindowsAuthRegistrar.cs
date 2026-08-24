using Microsoft.AspNetCore.Authentication.Negotiate;

namespace FwGpoWeb.Auth;

/// <summary>
/// Registers the Windows SSO handler (Negotiate: Kerberos with NTLM fallback).
/// Per the official ASP.NET Core 8 guidance, the Negotiate handler is used for
/// BOTH IIS-hosted and self-hosted (Kestrel) deployments — the legacy
/// "Windows authentication handler" was removed after .NET Core 2.x.
/// Compiled only for Windows builds / win RID targets (the package is
/// Windows-only); the app additionally refuses AuthMode=Windows at runtime
/// on non-Windows hosts.
/// </summary>
public static class WindowsAuthRegistrar
{
    public static void Register(IServiceCollection services)
    {
        services.AddAuthentication(options =>
        {
            options.DefaultScheme = NegotiateDefaults.AuthenticationScheme;
        })
        .AddNegotiate();
    }
}
