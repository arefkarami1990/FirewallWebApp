using System.Security.Claims;
using FwGpoWeb.Auth;
using FwGpoWeb.Services;

namespace FwGpoWeb.Middleware;

/// <summary>
/// Authorization gate for /api/*:
///   1. /api/auth/*        -> identity checks happen inside AuthController
///   2. /api/health        -> liveness open, diag requires admin
///   3. everything else    -> SSO identity -> verified cookie -> admin group
/// Answers machine-readable codes: SSO_REQUIRED / MFA_REQUIRED / FORBIDDEN.
/// </summary>
public sealed class ApiAuthorizationMiddleware
{
    private readonly RequestDelegate _next;
    private readonly IAdIdentity _adIdentity;
    private readonly VerifiedCookieService _verified;

    public ApiAuthorizationMiddleware(RequestDelegate next, IAdIdentity adIdentity, VerifiedCookieService verified)
    {
        _next = next;
        _adIdentity = adIdentity;
        _verified = verified;
    }

    public async Task InvokeAsync(HttpContext ctx)
    {
        if (!ctx.Request.Path.StartsWithSegments("/api"))
        {
            await _next(ctx);
            return;
        }

        var path = ctx.Request.Path.Value ?? "";
        if (path.StartsWith("/api/auth"))
        {
            await _next(ctx);
            return;
        }
        if (path == "/api/health" || path == "/api/health/")
        {
            await _next(ctx);
            return;
        }

        await ctx.Session.LoadAsync();

        // 1) SSO identity
        if (ctx.User.Identity?.IsAuthenticated != true || string.IsNullOrWhiteSpace(ctx.User.Identity.Name))
        {
            await RespondAsync(ctx, StatusCodes.Status401Unauthorized, "SSO_REQUIRED");
            return;
        }
        var upn = NormalizeUpn(ctx);

        // 2) MFA-verified (protected cookie bound to this identity)
        if (_verified.Validate(ctx, upn) is null)
        {
            await RespondAsync(ctx, StatusCodes.Status403Forbidden, "MFA_REQUIRED");
            return;
        }

        // 3) Admin group (cached 5 min in the session)
        var adminCached = ctx.Session.GetString("isAdmin") == "1";
        var ts = long.TryParse(ctx.Session.GetString("isAdminTs"), out var t) ? t : 0;
        bool isAdmin;
        if (adminCached && DateTimeOffset.UtcNow.ToUnixTimeSeconds() - ts < 300)
        {
            isAdmin = true;
        }
        else
        {
            (isAdmin, _) = await _adIdentity.ResolveAsync(upn, ctx.RequestAborted);
            ctx.Session.SetString("isAdmin", isAdmin ? "1" : "0");
            ctx.Session.SetString("isAdminTs", DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString());
        }
        if (!isAdmin)
        {
            await RespondAsync(ctx, StatusCodes.Status403Forbidden, "FORBIDDEN");
            return;
        }

        await _next(ctx);
    }

    private static string NormalizeUpn(HttpContext ctx)
    {
        var name = ctx.User.FindFirstValue(ClaimTypes.Name)
                     ?? (ctx.User.Identity?.IsAuthenticated == true ? ctx.User.Identity!.Name : "");
        if (name.Contains('\\'))
        {
            var i = name.IndexOf('\\');
            name = (name[(i + 1)..] + "@" + name[..i]).ToLowerInvariant();
        }
        return name;
    }

    private static Task RespondAsync(HttpContext ctx, int status, string code)
    {
        ctx.Response.StatusCode = status;
        ctx.Response.ContentType = "application/json";
        return ctx.Response.WriteAsJsonAsync(new { code });
    }
}
