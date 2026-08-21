using System.Security.Claims;

namespace FwGpoWeb.Middleware;

/// <summary>
/// DEV/TEST ONLY (AuthMode=Mock): simulates a domain-joined browser that has
/// completed the Kerberos SSO challenge, by assigning the configured mock
/// identity to HttpContext.User. Never active in production configuration.
/// </summary>
public sealed class MockAuthMiddleware
{
    private readonly RequestDelegate _next;
    private readonly string _mockUser;

    public MockAuthMiddleware(RequestDelegate next, string mockUser)
    {
        _next = next;
        _mockUser = mockUser;
    }

    public async Task InvokeAsync(HttpContext ctx)
    {
        if (ctx.User.Identity?.IsAuthenticated != true)
        {
            var upn = _mockUser.ToLowerInvariant();
            var claims = new List<Claim>
            {
                new(ClaimTypes.Name, upn),
                new(ClaimTypes.Upn, upn),
                new(ClaimTypes.NameIdentifier, upn)
            };
            var id = new ClaimsIdentity(claims, "MockWindows");
            ctx.User = new ClaimsPrincipal(id);
        }
        await _next(ctx);
    }
}
