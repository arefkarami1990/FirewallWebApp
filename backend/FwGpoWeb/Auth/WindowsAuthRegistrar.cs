using Microsoft.AspNetCore.Authentication.Negotiate;
using Microsoft.AspNetCore.Authentication.Windows;

namespace FwGpoWeb.Auth;

/// <summary>
/// Registers the Windows SSO handlers. Compiled only for Windows builds
/// (the Negotiate/Windows authentication assemblies are Windows-only).
/// </summary>
public static class WindowsAuthRegistrar
{
    public static void Register(IServiceCollection services)
    {
        // SSO: Negotiate (Kerberos with NTLM fallback) for self-hosted Kestrel;
        // the Windows authentication handler for IIS-hosted deployments (IIS
        // negotiates the ticket and hands the identity to the app).
        services.AddAuthentication(options =>
        {
            options.DefaultScheme = NegotiateDefaults.AuthenticationScheme;
        })
        .AddNegotiate()
        .AddWindowsAuthentication();
    }
}
