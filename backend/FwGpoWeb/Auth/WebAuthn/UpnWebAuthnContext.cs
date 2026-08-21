using System.Security.Claims;
using Microsoft.AspNetCore.Http;
using WebAuthn.Net.Models.Abstractions;
using WebAuthn.Net.Services.Context;

namespace FwGpoWeb.Auth.WebAuthn;

/// <summary>
/// WebAuthn operation context: the identity of the currently authenticated
/// (SSO) user. The UPN is resolved from the Windows/Kerberos identity, so a
/// user can only ever register or use credentials for their own account.
/// </summary>
public sealed class UpnWebAuthnContext : IWebAuthnContext
{
    public HttpContext HttpContext { get; }
    public string Upn { get; }

    public UpnWebAuthnContext(HttpContext httpContext, string upn)
    {
        HttpContext = httpContext ?? throw new ArgumentNullException(nameof(httpContext));
        Upn = upn;
    }

    public Task CommitAsync(CancellationToken cancellationToken) => Task.CompletedTask;
    public ValueTask DisposeAsync() => ValueTask.CompletedTask;
}

public sealed class UpnWebAuthnContextFactory : IWebAuthnContextFactory<UpnWebAuthnContext>
{
    public Task<UpnWebAuthnContext> CreateAsync(HttpContext httpContext, CancellationToken cancellationToken)
    {
        var identity = httpContext.User?.Identity;
        var upn = httpContext.User?.FindFirstValue(ClaimTypes.Name)
               ?? httpContext.User?.FindFirstValue(ClaimTypes.Upn)
               ?? (identity?.IsAuthenticated == true ? identity.Name : null);
        if (string.IsNullOrWhiteSpace(upn))
            throw new InvalidOperationException("WebAuthn requires an authenticated user.");
        return Task.FromResult(new UpnWebAuthnContext(httpContext, upn));
    }
}
