using System.Security.Claims;
using FwGpoWeb.Auth;
using FwGpoWeb.Auth.WebAuthn;
using FwGpoWeb.Models;
using FwGpoWeb.Services;
using Microsoft.AspNetCore.Mvc;
using WebAuthn.Net.Models.Protocol.Enums;
using WebAuthn.Net.Models.Protocol.Json.AuthenticationCeremony.VerifyAssertion;
using WebAuthn.Net.Models.Protocol.Json.RegistrationCeremony.CreateCredential;
using WebAuthn.Net.Models.Protocol.RegistrationCeremony.CreateOptions;
using WebAuthn.Net.Services.AuthenticationCeremony;
using WebAuthn.Net.Services.RegistrationCeremony;
using WebAuthn.Net.Services.RegistrationCeremony.Models.CreateOptions;
using WebAuthn.Net.Services.RegistrationCeremony.Models.CreateCredential;
using WebAuthn.Net.Services.AuthenticationCeremony.Models.CreateOptions;
using WebAuthn.Net.Services.AuthenticationCeremony.Models.VerifyAssertion;
using WebAuthn.Net.Services.Serialization.Cose.Models.Enums;

namespace FwGpoWeb.Controllers;

[ApiController]
[Route("api/auth")]
public class AuthController : ControllerBase
{
    private readonly UserSecretStore _secrets;
    private readonly TotpService _totp;
    private readonly LockoutService _lockout;
    private readonly AuditService _audit;
    private readonly IAdIdentity _adIdentity;
    private readonly IConfiguration _cfg;
    private readonly IRegistrationCeremonyService _regCeremony;
    private readonly IAuthenticationCeremonyService _authCeremony;
    private readonly VerifiedCookieService _verified;

    private const string SessionUpn = "upn";
    private const string SessionName = "name";
    private const string SessionAdmin = "isAdmin";
    private const string SessionAdminTs = "isAdminTs";
    private const string WaRegId = "waRegId";
    private const string WaMfaId = "waMfaId";

    public AuthController(
        UserSecretStore secrets,
        TotpService totp,
        LockoutService lockout,
        AuditService audit,
        IAdIdentity adIdentity,
        IConfiguration cfg,
        IRegistrationCeremonyService regCeremony,
        IAuthenticationCeremonyService authCeremony,
        VerifiedCookieService verified)
    {
        _secrets = secrets;
        _totp = totp;
        _lockout = lockout;
        _audit = audit;
        _adIdentity = adIdentity;
        _cfg = cfg;
        _regCeremony = regCeremony;
        _authCeremony = authCeremony;
        _verified = verified;
    }

    private string Upn => NormalizeUpn(User.FindFirstValue(ClaimTypes.Name)
                            ?? User.FindFirstValue(ClaimTypes.Upn)
                            ?? (User.Identity?.IsAuthenticated == true ? User.Identity.Name! : ""));

    /// <summary>
    /// Normalizes "DOMAIN\\user" (Windows auth) to "user@domain".
    /// </summary>
    private static string NormalizeUpn(string s)
    {
        if (string.IsNullOrWhiteSpace(s)) return "";
        if (s.Contains('@')) return s.ToLowerInvariant();
        var i = s.IndexOf('\\');
        if (i > 0 && i < s.Length - 1)
            return (s[(i + 1)..] + "@" + s[..i]).ToLowerInvariant();
        return s.ToLowerInvariant();
    }

    private string ClientIp => HttpContext.Connection.RemoteIpAddress?.ToString() ?? "";

    private (string Upn, string Name) CurrentUser()
    {
        var upn = Upn;
        if (string.IsNullOrWhiteSpace(upn))
            throw new UnauthorizedAccessException("not authenticated");
        var name = User.FindFirstValue(ClaimTypes.GivenName) ?? upn.Split('@')[0];
        return (upn, name);
    }

    private bool IsAdminCached()
    {
        var admin = HttpContext.Session.GetString(SessionAdmin) == "1";
        var ts = long.TryParse(HttpContext.Session.GetString(SessionAdminTs), out var t) ? t : 0;
        if (admin && DateTimeOffset.UtcNow.ToUnixTimeSeconds() - ts < 300) return true;
        return false;
    }

    // ------------------------------------------------------------------
    // Status / bootstrap
    // ------------------------------------------------------------------

    [HttpGet("status")]
    public async Task<IActionResult> Status()
    {
        var (upn, name) = (Upn, User.Identity?.IsAuthenticated == true ? Upn.Split('@')[0] : null);
        var authenticated = User.Identity?.IsAuthenticated == true && !string.IsNullOrWhiteSpace(upn);
        var status = new AuthStatus { Authenticated = authenticated, Upn = authenticated ? upn : null, Name = name };
        if (authenticated)
        {
            status.Verified = _verified.Validate(HttpContext, upn) is not null;
            var secrets = await _secrets.LoadAsync(upn);
            status.TotpConfigured = secrets.Totp is not null;
            status.FidoConfigured = secrets.Fido.Count > 0;
            if (_lockout.IsLocked(upn, out var rem))
            {
                status.Locked = true;
                status.LockRemainingSec = rem;
            }
            if (status.Verified)
            {
                if (IsAdminCached()) status.IsAdmin = true;
                else
                {
                    var (isAdmin, _) = await _adIdentity.ResolveAsync(upn, HttpContext.RequestAborted);
                    status.IsAdmin = isAdmin;
                    HttpContext.Session.SetString(SessionAdmin, isAdmin ? "1" : "0");
                    HttpContext.Session.SetString(SessionAdminTs, DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString());
                }
            }
        }
        return Ok(status);
    }

    /// <summary>
    /// SSO bootstrap. With Windows auth (IIS/Kestrel) the identity is already
    /// present; when it is not, we answer 401 + WWW-Authenticate so the
    /// browser performs the Kerberos/NTLM challenge.
    /// </summary>
    [HttpGet("sso")]
    public async Task<IActionResult> Sso()
    {
        if (User.Identity?.IsAuthenticated == true && !string.IsNullOrWhiteSpace(Upn))
        {
            await HttpContext.Session.LoadAsync();
            HttpContext.Session.SetString(SessionUpn, Upn);
            HttpContext.Session.SetString(SessionName, Upn.Split('@')[0]);
            HttpContext.Session.Remove(SessionAdmin);
            HttpContext.Session.Remove(SessionAdminTs);
            return Ok(new { ok = true, upn = Upn });
        }
        if (OperatingSystem.IsWindows())
            Response.Headers["WWW-Authenticate"] = "Negotiate";
        Response.StatusCode = StatusCodes.Status401Unauthorized;
        return Unauthorized(new { code = "SSO_REQUIRED" });
    }

    [HttpGet("logout")]
    [ResponseCache(NoStore = true)]
    public async Task<IActionResult> Logout()
    {
        await HttpContext.Session.LoadAsync();
        HttpContext.Session.Clear();
        _verified.Remove(HttpContext);
        await _audit.LogAsync(Upn, "LOGOUT", "session terminated", true, ClientIp);
        return Ok(new { ok = true });
    }

    [HttpGet("csrf")]
    public IActionResult Csrf([FromServices] Microsoft.AspNetCore.Antiforgery.IAntiforgery af)
    {
        if (User.Identity?.IsAuthenticated != true) return Unauthorized();
        return Ok(new { token = af.GetAndStoreTokens(HttpContext).RequestToken });
    }

    // ------------------------------------------------------------------
    // TOTP MFA
    // ------------------------------------------------------------------

    [HttpGet("totp/setup")]
    public async Task<IActionResult> TotpSetup()
    {
        var (upn, _) = CurrentUser();
        var secrets = await _secrets.LoadAsync(upn);
        string secret;
        if (secrets.Totp is not null)
        {
            secret = secrets.Totp.SecretB32; // re-issuing the QR for an existing secret
        }
        else
        {
            secret = TotpService.GenerateSecretB32();
            // NOTE: not persisted yet; persisted only when the first code confirms it.
        }
        var issuer = _cfg["WebAuthn:RpName"] ?? "FW-GPO Builder";
        var uri = _totp.OtpAuthUri(upn, secret, issuer);
        return Ok(new TotpSetupResponse
        {
            Secret = secret,
            OtpauthUri = uri,
            QrPngDataUrl = _totp.QrPngDataUrl(uri)
        });
    }

    [HttpPost("totp/confirm")]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> TotpConfirm([FromBody] TotpConfirmRequest req)
    {
        var (upn, _) = CurrentUser();
        if (_lockout.IsLocked(upn, out _))
            return StatusCode(423, new { code = "LOCKED" });

        // Generate-on-confirm model: the client sends back the secret it
        // received from /totp/setup plus the first code. The secret is
        // persisted only after the code validates.
        var secret = req.SetupSecret;
        if (string.IsNullOrWhiteSpace(secret) || secret.Length is < 16 or > 64
            || !secret.All(c => char.ToUpperInvariant(c) is >= 'A' and <= 'Z' || c is >= '2' and <= '7' || c == '='))
            return BadRequest(new { error = "Invalid TOTP secret." });

        if (!_totp.Validate(req.Code, secret))
        {
            _lockout.RegisterFailure(upn, out _);
            await _audit.LogAsync(upn, "MFA_TOTP_FAIL", "invalid code", false, ClientIp);
            return BadRequest(new { error = "Invalid code." });
        }
        var secrets = await _secrets.LoadAsync(upn);
        secrets.Totp = new TotpSecret { SecretB32 = secret, CreatedAt = DateTimeOffset.UtcNow };
        await _secrets.SaveAsync(upn, secrets);
        _lockout.Reset(upn);
        await _audit.LogAsync(upn, "MFA_TOTP_ENROLLED", "TOTP secret stored", true, ClientIp);
        return Ok(new { ok = true });
    }

    // ------------------------------------------------------------------
    // FIDO2 / WebAuthn (registration + MFA)
    // ------------------------------------------------------------------

    [HttpGet("fido/register/begin")]
    public async Task<IActionResult> FidoRegisterBegin()
    {
        var (upn, name) = CurrentUser();
        var userHandle = WebAuthnCredentialSerializer.UpnToUserHandle(upn);
        var req = new BeginRegistrationCeremonyRequest(
            origins: new RegistrationCeremonyOriginParameters(Origins()),
            topOrigins: null,
            rpDisplayName: _cfg["WebAuthn:RpName"] ?? "FW-GPO Builder",
            user: new PublicKeyCredentialUserEntity(upn, userHandle, name),
            challengeSize: 32,
            pubKeyCredParams: new[] { CoseAlgorithm.ES256, CoseAlgorithm.RS256, CoseAlgorithm.ES384, CoseAlgorithm.ES512 },
            timeout: null,
            excludeCredentials: new RegistrationCeremonyExcludeCredentials(true, false, null),
            authenticatorSelection: new AuthenticatorSelectionCriteria(
                authenticatorAttachment: null,
                residentKey: ResidentKeyRequirement.Required,
                requireResidentKey: null,
                userVerification: UserVerificationRequirement.Preferred),
            hints: null,
            attestation: AttestationConveyancePreference.None,
            attestationFormats: null,
            extensions: null);
        var result = await _regCeremony.BeginCeremonyAsync(HttpContext, req, HttpContext.RequestAborted);
        HttpContext.Session.SetString(WaRegId, result.RegistrationCeremonyId);
        await _audit.LogAsync(upn, "FIDO_REG_BEGIN", "registration ceremony started", true, ClientIp);
        return Ok(new FidoRegistrationBeginResponse
        {
            Options = System.Text.Json.JsonSerializer.SerializeToElement(result.Options),
            UserHandle = Convert.ToBase64String(userHandle)
        });
    }

    [HttpPost("fido/register/complete")]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> FidoRegisterComplete([FromBody] FidoRegistrationCompleteRequest req)
    {
        var (upn, _) = CurrentUser();
        var ceremonyId = HttpContext.Session.GetString(WaRegId);
        if (string.IsNullOrEmpty(ceremonyId))
            return BadRequest(new { error = "No active registration ceremony." });

        RegistrationResponseJSON? responseJson;
        try
        {
            responseJson = System.Text.Json.JsonSerializer.Deserialize<RegistrationResponseJSON>(req.Credential.GetRawText());
        }
        catch
        {
            return BadRequest(new { error = "Malformed credential payload." });
        }
        if (responseJson is null) return BadRequest(new { error = "Malformed credential payload." });

        var result = await _regCeremony.CompleteCeremonyAsync(HttpContext,
            new CompleteRegistrationCeremonyRequest(ceremonyId, req.Description, responseJson), HttpContext.RequestAborted);
        HttpContext.Session.Remove(WaRegId);
        if (result.HasError)
        {
            await _audit.LogAsync(upn, "FIDO_REG_FAIL", "registration verification failed", false, ClientIp);
            return BadRequest(new { error = "Registration verification failed." });
        }
        await _audit.LogAsync(upn, "FIDO_REG_OK", "credential registered", true, ClientIp);
        return Ok(new { ok = true });
    }

    [HttpGet("fido/list")]
    public async Task<IActionResult> FidoList()
    {
        var (upn, _) = CurrentUser();
        var secrets = await _secrets.LoadAsync(upn);
        return Ok(new {
            credentials = secrets.Fido.Select(f => new { id = f.CredIdB64, description = f.Description, createdAt = f.CreatedAt })
        });
    }

    [HttpDelete("fido/{credIdB64}")]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> FidoDelete(string credIdB64)
    {
        var (upn, _) = CurrentUser();
        if (!credIdB64.All(c => char.IsLetterOrDigit(c) || c is '+' or '/' or '='))
            return BadRequest(new { error = "Invalid credential id." });
        await _secrets.DeleteFidoCredentialAsync(upn, credIdB64);
        await _audit.LogAsync(upn, "FIDO_DELETE", credIdB64, true, ClientIp);
        return Ok(new { ok = true });
    }

    [HttpGet("fido/mfa/begin")]
    public async Task<IActionResult> FidoMfaBegin()
    {
        var (upn, _) = CurrentUser();
        var secrets = await _secrets.LoadAsync(upn);
        if (secrets.Fido.Count == 0)
            return BadRequest(new { error = "No FIDO2 credentials registered. Register one first." });
        var userHandle = WebAuthnCredentialSerializer.UpnToUserHandle(upn);
        var req = new BeginAuthenticationCeremonyRequest(
            origins: new AuthenticationCeremonyOriginParameters(Origins()),
            topOrigins: null,
            userHandle: userHandle,
            challengeSize: 32,
            timeout: null,
            allowCredentials: new AuthenticationCeremonyIncludeCredentials(true, false, null),
            userVerification: UserVerificationRequirement.Preferred,
            hints: null,
            extensions: null);
        var result = await _authCeremony.BeginCeremonyAsync(HttpContext, req, HttpContext.RequestAborted);
        HttpContext.Session.SetString(WaMfaId, result.AuthenticationCeremonyId);
        return Ok(new FidoMfaBeginResponse
        {
            Options = System.Text.Json.JsonSerializer.SerializeToElement(result.Options),
            UserHandle = Convert.ToBase64String(userHandle)
        });
    }

    // ------------------------------------------------------------------
    // MFA complete (TOTP or WebAuthn) -> session becomes Verified + rotated
    // ------------------------------------------------------------------

    [HttpPost("mfa/complete")]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> MfaComplete([FromBody] MfaCompleteRequest req)
    {
        var (upn, _) = CurrentUser();
        if (_lockout.IsLocked(upn, out var rem))
            return StatusCode(423, new { code = "LOCKED", remainingSec = rem });

        bool ok = req.Method?.ToLowerInvariant() switch
        {
            "totp" => await CompleteTotpAsync(req, upn),
            "webauthn" => await CompleteWebAuthnAsync(req, upn),
            _ => false
        };

        if (!ok)
        {
            var nowLocked = _lockout.RegisterFailure(upn, out _);
            await _audit.LogAsync(upn, $"MFA_{(req.Method ?? "?").ToUpperInvariant()}_FAIL",
                nowLocked ? "locked after repeated failures" : "mfa verification failed", false, ClientIp);
            return BadRequest(new { error = nowLocked ? "Too many failed attempts. Account locked." : "Verification failed." });
        }

        // Success:
        //  - wipe the unverified session state (fixation break: nothing
        //    accumulated before MFA survives)
        //  - issue the integrity-protected verified cookie bound to this
        //    identity for the absolute session lifetime
        _lockout.Reset(upn);
        await HttpContext.Session.LoadAsync();
        HttpContext.Session.Clear();
        HttpContext.Session.SetString(SessionUpn, upn);
        HttpContext.Session.SetString(SessionName, upn.Split('@')[0]);
        HttpContext.Session.Remove(SessionAdmin);
        HttpContext.Session.Remove(SessionAdminTs);
        _verified.Issue(HttpContext, upn, req.Method!.ToLowerInvariant());
        await _audit.LogAsync(upn, "MFA_OK", $"verified via {req.Method}", true, ClientIp);
        return Ok(new { ok = true });
    }

    private async Task<bool> CompleteTotpAsync(MfaCompleteRequest req, string upn)
    {
        var secrets = await _secrets.LoadAsync(upn);
        if (secrets.Totp is null) return false;
        return _totp.Validate(req.Code, secrets.Totp.SecretB32);
    }

    private async Task<bool> CompleteWebAuthnAsync(MfaCompleteRequest req, string upn)
    {
        var ceremonyId = HttpContext.Session.GetString(WaMfaId);
        if (string.IsNullOrEmpty(ceremonyId)) return false;
        if (req.Credential is null) return false;
        AuthenticationResponseJSON? responseJson;
        try
        {
            responseJson = System.Text.Json.JsonSerializer.Deserialize<AuthenticationResponseJSON>(req.Credential.Value.GetRawText());
        }
        catch { return false; }
        if (responseJson is null) return false;
        var result = await _authCeremony.CompleteCeremonyAsync(HttpContext,
            new CompleteAuthenticationCeremonyRequest(ceremonyId, responseJson), HttpContext.RequestAborted);
        HttpContext.Session.Remove(WaMfaId);
        return !result.HasError;
    }

    private string[] Origins()
    {
        var origins = _cfg.GetSection("WebAuthn:Origins").Get<string[]>() ?? Array.Empty<string>();
        if (origins.Length == 0)
        {
            var host = Request.Host.Value ?? "localhost";
            origins = new[] { $"{Request.Scheme}://{host}" };
        }
        return origins;
    }
}
