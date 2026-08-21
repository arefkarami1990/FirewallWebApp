using System.Text.Encodings.Web;
using Microsoft.AspNetCore.DataProtection;
using FwGpoWeb.Auth;
using FwGpoWeb.Auth.WebAuthn;
using FwGpoWeb.Middleware;
using FwGpoWeb.Security;
using FwGpoWeb.Services;
#if FwGpoWindows
using Microsoft.AspNetCore.Authentication.Negotiate;
using Microsoft.AspNetCore.Authentication.Windows;
#endif
using WebAuthn.Net.Configuration.DependencyInjection;

var builder = WebApplication.CreateBuilder(args);

var appCfg = builder.Configuration.GetSection("App");
var authMode = appCfg["AuthMode"] ?? "Windows";
var hosting = appCfg["Hosting"] ?? "Iis";
var dataDir = string.IsNullOrWhiteSpace(appCfg["DataDir"])
    ? (OperatingSystem.IsWindows()
        ? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "FwGpoWeb")
        : Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".fwgpoweb"))
    : appCfg["DataDir"];
Directory.CreateDirectory(dataDir);

// ---------------------------------------------------------------------------
// Host (Kestrel when self-hosted; IIS when hosted in IIS)
// ---------------------------------------------------------------------------
if (hosting.Equals("Kestrel", StringComparison.OrdinalIgnoreCase))
{
    var url = appCfg["KestrelUrl"] ?? "http://0.0.0.0:5000";
    builder.WebHost.UseUrls(url);
}

// ---------------------------------------------------------------------------
// Authentication (Windows SSO / Kerberos) or Mock (dev)
// ---------------------------------------------------------------------------
if (authMode.Equals("Windows", StringComparison.OrdinalIgnoreCase))
{
    if (!OperatingSystem.IsWindows())
        throw new InvalidOperationException("AuthMode=Windows requires a Windows host. Use AuthMode=Mock for development.");
#if FwGpoWindows
    FwGpoWeb.Auth.WindowsAuthRegistrar.Register(builder.Services);
#else
    throw new InvalidOperationException(
        "AuthMode=Windows requires a Windows build (Negotiate/Windows authentication assemblies are Windows-only).");
#endif
    builder.Services.AddAuthorization(options =>
    {
        options.FallbackPolicy = new Microsoft.AspNetCore.Authorization.AuthorizationPolicyBuilder()
            .RequireAuthenticatedUser().Build();
    });
}
else
{
    builder.Services.AddAuthorization();
}

// ---------------------------------------------------------------------------
// Session (cookie-based, HttpOnly, SameSite=Lax, SecurePolicy=SameAsRequest)
// ---------------------------------------------------------------------------
builder.Services.AddDistributedMemoryCache();
builder.Services.AddSession(options =>
{
    options.Cookie.Name = appCfg["SessionCookieName"] ?? "FwGpo.Sid";
    options.Cookie.HttpOnly = true;
    options.Cookie.SameSite = SameSiteMode.Lax;
    options.Cookie.SecurePolicy = CookieSecurePolicy.SameAsRequest;
    options.IdleTimeout = TimeSpan.FromMinutes(int.Parse(appCfg["SessionIdleMinutes"] ?? "30"));
    options.Cookie.MaxAge = TimeSpan.FromHours(int.Parse(appCfg["SessionAbsoluteHours"] ?? "8"));
});

// ---------------------------------------------------------------------------
// Core services
// ---------------------------------------------------------------------------
builder.Services.AddDataProtection()
    .PersistKeysToFileSystem(new DirectoryInfo(Path.Combine(dataDir, "dataprotection-keys")))
    .SetApplicationName("FwGpoWeb");

// AddControllersWithViews (instead of AddControllers) is required in .NET 8
// so that [ValidateAntiForgeryToken] resolves the antiforgery filter services
// on API controllers.
builder.Services.AddControllersWithViews()
    .AddJsonOptions(o => o.JsonSerializerOptions.Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping);

builder.Services.AddAntiforgery(o => o.HeaderName = "RequestVerificationToken");

builder.Services.AddSingleton(new TotpService());
builder.Services.AddSingleton(sp => new UserSecretStore(dataDir));
builder.Services.AddSingleton(sp => new LockoutService(
    int.Parse(builder.Configuration["Security:MfaMaxAttempts"] ?? "5"),
    int.Parse(builder.Configuration["Security:MfaLockoutMinutes"] ?? "15")));
builder.Services.AddSingleton(sp => new AuditService(dataDir));
builder.Services.AddSingleton(sp => new VerifiedCookieService(
    sp.GetRequiredService<Microsoft.AspNetCore.DataProtection.IDataProtectionProvider>(),
    int.Parse(appCfg["SessionAbsoluteHours"] ?? "8")));

// AD identity (via the PowerShell/AD bridge; mock in dev)
bool adMock = bool.Parse(builder.Configuration["Ad:Mock"] ?? "false");
var adminGroups = builder.Configuration.GetSection("App:AdminGroups").Get<string[]>() ?? new[] { "Domain Admins" };
builder.Services.AddSingleton<IAdIdentity>(sp => adMock
    ? new MockAdIdentity(adminGroups, bool.Parse(appCfg["MockIsAdmin"] ?? "true"))
    : new PwshAdIdentity(sp.GetRequiredService<IPwshBridge>(), adminGroups));

// PowerShell bridge (real) or mock AD
var pwshCfg = builder.Configuration.GetSection("Pwsh");
builder.Services.AddSingleton<IPwshBridge>(sp => adMock
    ? new MockPwshBridge()
    : new PwshBridge(
        new PwshConfig(pwshCfg["Exe"] ?? "powershell.exe", pwshCfg["ModuleDir"] ?? "", int.Parse(pwshCfg["TimeoutSeconds"] ?? "300")),
        dataDir));

builder.Services.AddSingleton<GpoService>();

// WebAuthn (FIDO2 / fingerprint)
// NOTE: FIDO metadata ingestion failures (offline domains, rate limits) must
// NOT crash the host — attestation verification still works with the
// built-in trust roots; metadata only adds extra authenticator checks.
builder.Services.AddWebAuthnCore<UpnWebAuthnContext>(
    options => { },
    httpClientBuilder => { },
    fidoIngest =>
    {
        fidoIngest.ThrowExceptionOnFailure = false;
        fidoIngest.IngestInterval = TimeSpan.FromHours(12);
    })
    // Ceremony-state cookies (webauthnr / webauthna) default to
    // SecurePolicy=Always + SameSite=None, which breaks non-HTTPS dev
    // environments (and triggers a SameSite=None-requires-Secure warning).
    // WebAuthn ceremonies are same-origin, so Lax + SameAsRequest is the
    // correct, safer setting: Secure on HTTPS (production), plain on local
    // HTTP (dev).
    .AddDefaultStorages(
        reg => { reg.Cookie.SecurePolicy = CookieSecurePolicy.SameAsRequest; reg.Cookie.SameSite = SameSiteMode.Lax; },
        auth => { auth.Cookie.SecurePolicy = CookieSecurePolicy.SameAsRequest; auth.Cookie.SameSite = SameSiteMode.Lax; })
    .AddContextFactory<UpnWebAuthnContext, UpnWebAuthnContextFactory>()
    .AddCredentialStorage<UpnWebAuthnContext, UpnCredentialStorage>();

// WORKAROUND (WebAuthn.Net 2.1.0): the FIDO MDS3 background-ingest hosted
// service throws an UNHANDLED HttpRequestException when the FIDO server
// answers with an error status (e.g. HTTP 429 rate limit) — the library's
// ThrowExceptionOnFailure guard sits below the HttpClient call, so the
// exception crashes the host at startup. FIDO metadata is optional for us
// (attestation verification falls back to built-in trust roots), so the
// ingestion service is removed entirely. Re-enable by deleting this block
// once upstream fixes the unhandled exception.
{
    var hostedType = typeof(WebAuthn.Net.Services.FidoMetadata.Implementation.FidoMetadataBackgroundIngest.FidoMetadataBackgroundIngestHostedService);
    var toRemove = builder.Services
        .Where(d => d.ServiceType == hostedType ||
                    (d.ServiceType == typeof(Microsoft.Extensions.Hosting.IHostedService) && d.ImplementationType == hostedType))
        .ToArray();
    foreach (var d in toRemove) builder.Services.Remove(d);
}

// ---------------------------------------------------------------------------
// Rate limiting (per IP): 20/min on /api/auth/*, 300/min elsewhere
// ---------------------------------------------------------------------------
builder.Services.AddRateLimiter(options =>
{
    options.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
    // Sensitive auth endpoints (MFA verify, TOTP confirm, SSO, FIDO complete)
    // are throttled per IP (60/min = max 1/second; the 5-attempt lockout is
    // the primary brute-force defense, rate limiting is the secondary layer);
    // everything else 300/min.
    var sensitivePaths = new[]
    {
        "/api/auth/mfa/complete", "/api/auth/totp/confirm", "/api/auth/sso",
        "/api/auth/fido/register/complete", "/api/auth/fido/mfa/begin", "/api/auth/fido/register/begin"
    };
    options.GlobalLimiter = System.Threading.RateLimiting.PartitionedRateLimiter.Create<HttpContext, string>(ctx =>
    {
        var ip = ctx.Connection.RemoteIpAddress?.ToString() ?? "?";
        var path = ctx.Request.Path.Value ?? "";
        var sensitive = sensitivePaths.Any(p => path.StartsWith(p, StringComparison.OrdinalIgnoreCase));
        int limit = sensitive ? 60 : 300;
        return System.Threading.RateLimiting.RateLimitPartition.GetFixedWindowLimiter(
            $"{(sensitive ? "sens-" : "api-")}{ip}",
            _ => new System.Threading.RateLimiting.FixedWindowRateLimiterOptions
            {
                Window = TimeSpan.FromMinutes(1),
                PermitLimit = limit,
                QueueLimit = 0
            });
    });
});

var app = builder.Build();

// ---------------------------------------------------------------------------
// Pipeline
// ---------------------------------------------------------------------------
app.UseHsts();
app.UseMiddleware<SecurityHeadersMiddleware>();
app.UseRateLimiter();

if (authMode.Equals("Mock", StringComparison.OrdinalIgnoreCase))
    app.UseMiddleware<MockAuthMiddleware>(appCfg["MockUser"] ?? "admin@corp.local");

app.UseRouting();
app.UseSession();

if (authMode.Equals("Windows", StringComparison.OrdinalIgnoreCase))
    app.UseAuthentication();

app.UseMiddleware<ApiAuthorizationMiddleware>();
if (authMode.Equals("Windows", StringComparison.OrdinalIgnoreCase))
    app.UseAuthorization();
app.UseAntiforgery();
app.UseStaticFiles();

app.MapControllers();

// SPA fallback (GET, non-file, non-api)
app.MapGet("/{*path}", (HttpContext ctx) =>
{
    if (ctx.Request.Path.StartsWithSegments("/api"))
        return Results.NotFound();
    var webEnv = ctx.RequestServices.GetRequiredService<IWebHostEnvironment>();
    var indexFile = Path.Combine(webEnv.WebRootPath ?? Path.Combine(AppContext.BaseDirectory, "wwwroot"), "index.html");
    if (!File.Exists(indexFile)) return Results.NotFound();
    return Results.File(File.ReadAllBytes(indexFile), "text/html");
});

app.Run();

namespace FwGpoWeb { public partial class Program { } }
