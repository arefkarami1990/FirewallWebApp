using System.Security.Claims;
using System.Text.Json;
using FwGpoWeb.Models;
using FwGpoWeb.Security;
using FwGpoWeb.Services;
using Microsoft.AspNetCore.Mvc;

namespace FwGpoWeb.Controllers;

[ApiController]
[Route("api/ad")]
public class AdController : Controller
{
    private readonly GpoService _gpo;
    private readonly IPwshBridge _bridge;
    private readonly AuditService _audit;

    public AdController(GpoService gpo, IPwshBridge bridge, AuditService audit)
    {
        _gpo = gpo;
        _bridge = bridge;
        _audit = audit;
    }

    private static string NormUpn(HttpContext ctx)
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

    [HttpGet("ous")]
    public async Task<IActionResult> Ous(CancellationToken ct)
    {
        var actor = NormUpn(HttpContext);
        try
        {
            var ous = await _gpo.ListOusAsync(ct);
            await _audit.LogAsync(actor, "AD_LIST_OUS", $"count={ous.Count}", true, Ip());
            return Ok(new { ous });
        }
        catch (Exception ex)
        {
            await _audit.LogAsync(actor, "AD_LIST_OUS_FAIL", ex.Message, false, Ip());
            return BadRequest(new { error = "Failed to list OUs." });
        }
    }

    [HttpGet("ou/check")]
    public async Task<IActionResult> OuCheck([FromQuery] string? dn, CancellationToken ct)
    {
        var actor = NormUpn(HttpContext);
        if (!InputValidator.IsValidDn(dn))
            return BadRequest(new { error = "Invalid OU DN.", exists = false });
        var (ok, data, err) = await _bridge.RunAsync("test-ou", new { dn }, ct);
        var exists = ok && data.HasValue && data.Value.TryGetProperty("exists", out var exEl) && exEl.ValueKind == JsonValueKind.True;
        await _audit.LogAsync(actor, "AD_OU_CHECK", $"dn={dn} exists={exists}", true, Ip());
        return Ok(new { exists });
    }

    private string Ip() => HttpContext.Connection.RemoteIpAddress?.ToString() ?? "";
}
