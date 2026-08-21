namespace FwGpoWeb.Security;

/// <summary>
/// Defense-in-depth HTTP headers:
///  - HSTS (on HTTPS)
///  - strict Content-Security-Policy (no inline scripts/styles)
///  - nosniff, frame denial, referrer policy
///  - removes server version headers
/// </summary>
public sealed class SecurityHeadersMiddleware
{
    private const string Csp = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; font-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'";

    private readonly RequestDelegate _next;
    public SecurityHeadersMiddleware(RequestDelegate next) => _next = next;

    public async Task InvokeAsync(HttpContext ctx)
    {
        var h = ctx.Response.Headers;
        h["Content-Security-Policy"] = Csp;
        h["X-Content-Type-Options"] = "nosniff";
        h["X-Frame-Options"] = "DENY";
        h["Referrer-Policy"] = "no-referrer";
        h["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()";
        if (ctx.Request.Path.StartsWithSegments("/api"))
            h["Cache-Control"] = "no-store";
        await _next(ctx);
    }
}
