using System.Security.Claims;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Http;

namespace FwGpoWeb.Auth;

public sealed record VerifiedPayload(string Upn, string Method, long IssuedUtc);

/// <summary>
/// MFA-verified state is carried in a DATA-PROTECTION-ENCRYPTED + integrity
/// protected cookie (FwGpo.Verified) rather than in the session:
///   - issued only after a successful MFA verification
///   - bound to the SSO identity (upn) at issue time; a mismatch at read
///     time (e.g. session fixation / cookie replay by another identity) fails
///   - has its own absolute lifetime (independent of the idle session)
///   - issuing it at MFA time is the session-fixation break: the verified
///     marker is a fresh, protected value the attacker does not possess.
/// The plain session is additionally cleared at MFA completion so no
/// unverified-session state leaks into the verified context.
/// </summary>
public sealed class VerifiedCookieService
{
    public const string CookieName = "FwGpo.Verified";
    private static readonly JsonSerializerOptions JsonOpts = new() { WriteIndented = false };

    private readonly IDataProtector _protector;
    private readonly TimeSpan _lifetime;

    public VerifiedCookieService(IDataProtectionProvider dp, int absoluteHours)
    {
        _protector = dp.CreateProtector("FwGpoWeb.VerifiedCookie.v1");
        _lifetime = TimeSpan.FromHours(absoluteHours);
    }

    public void Issue(HttpContext ctx, string upn, string method)
    {
        ctx.Response.Cookies.Delete(CookieName);
        var payload = new VerifiedPayload(upn, method, DateTimeOffset.UtcNow.ToUnixTimeSeconds());
        var json = JsonSerializer.Serialize(payload, JsonOpts);
        var token = _protector.Protect(json);
        var builder = new CookieBuilder
        {
            HttpOnly = true,
            IsEssential = true,
            SameSite = SameSiteMode.Lax,
            SecurePolicy = CookieSecurePolicy.SameAsRequest,
            MaxAge = _lifetime,
            Path = "/"
        };
        ctx.Response.Cookies.Append(CookieName, token, builder.Build(ctx));
    }

    public void Remove(HttpContext ctx) => ctx.Response.Cookies.Delete(CookieName);

    /// <returns>The verified UPN if the cookie is valid for <paramref name="expectedUpn"/>, else null.</returns>
    public string? Validate(HttpContext ctx, string expectedUpn)
    {
        var token = ctx.Request.Cookies[CookieName];
        if (string.IsNullOrWhiteSpace(token)) return null;
        string? json;
        try { json = _protector.Unprotect(token); }
        catch { return null; }
        VerifiedPayload? p;
        try { p = JsonSerializer.Deserialize<VerifiedPayload>(json, JsonOpts); }
        catch { return null; }
        if (p is null) return null;
        // identity binding + freshness
        if (!string.Equals(p.Upn, expectedUpn, StringComparison.OrdinalIgnoreCase)) return null;
        var age = DateTimeOffset.UtcNow.ToUnixTimeSeconds() - p.IssuedUtc;
        if (age < -900 || age > (long)_lifetime.TotalSeconds) return null; // small clock skew tolerance
        return p.Upn;
    }
}
