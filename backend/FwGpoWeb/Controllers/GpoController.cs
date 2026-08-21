using System.Security.Claims;
using FwGpoWeb.Models;
using FwGpoWeb.Services;
using Microsoft.AspNetCore.Mvc;

namespace FwGpoWeb.Controllers;

[ApiController]
[Route("api/gpo")]
public class GpoController : Controller
{
    private readonly GpoService _gpo;

    public GpoController(GpoService gpo) => _gpo = gpo;

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

    private string Ip() => HttpContext.Connection.RemoteIpAddress?.ToString() ?? "";

    [HttpPost("search")]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Search([FromBody] SearchGpoRequest req, CancellationToken ct)
    {
        var actor = NormUpn(HttpContext);
        try
        {
            var r = await _gpo.SearchGpoAsync(req, actor, ct);
            return Ok(r);
        }
        catch (ValidationFailureException ex)
        {
            return BadRequest(new { error = ex.Message });
        }
        catch (Exception)
        {
            return StatusCode(502, new { error = "Directory service operation failed." });
        }
    }

    [HttpGet("list")]
    public async Task<IActionResult> List(CancellationToken ct)
    {
        try
        {
            var gpos = await _gpo.ListGposAsync(ct);
            return Ok(new { gpos });
        }
        catch (Exception)
        {
            return StatusCode(502, new { error = "Failed to list GPOs." });
        }
    }

    [HttpPost("apply")]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Apply([FromBody] ApplyGpoRequest req, CancellationToken ct)
    {
        var actor = NormUpn(HttpContext);
        try
        {
            var r = await _gpo.ApplyGpoAsync(req, actor, Ip(), ct);
            return Ok(r);
        }
        catch (ValidationFailureException ex)
        {
            return BadRequest(new { error = ex.Message });
        }
        catch (Exception)
        {
            return StatusCode(502, new { error = "Directory service operation failed." });
        }
    }

    [HttpGet("rules")]
    public async Task<IActionResult> Rules([FromQuery] string gpoName, [FromQuery] int port, [FromQuery] bool portIsAny, CancellationToken ct)
    {
        var actor = NormUpn(HttpContext);
        try
        {
            var (allows, blocks) = await _gpo.GetRulesAsync(gpoName, port, portIsAny, actor, ct);
            return Ok(new { allows, blocks });
        }
        catch (ValidationFailureException ex)
        {
            return BadRequest(new { error = ex.Message });
        }
        catch (Exception)
        {
            return StatusCode(502, new { error = "Failed to read GPO rules." });
        }
    }
}
