using FwGpoWeb.Models;
using FwGpoWeb.Services;
using Microsoft.AspNetCore.Mvc;

namespace FwGpoWeb.Controllers;

[ApiController]
[Route("api/health")]
public class HealthController : Controller
{
    private readonly GpoService _gpo;

    public HealthController(GpoService gpo) => _gpo = gpo;

    [HttpGet]
    [ResponseCache(NoStore = true)]
    public IActionResult Liveness() => Ok(new { status = "ok", version = "1.0.0" });

    /// <summary>Admin-only deep health check: DC reachability + service identity.</summary>
    [HttpGet("diag")]
    public async Task<IActionResult> Diag(CancellationToken ct)
    {
        try
        {
            var info = await _gpo.PingDcAsync("diag", ct);
            return Ok(new { dc = info, pwsh = "ready" });
        }
        catch (Exception ex)
        {
            return Ok(new { dc = (object?)null, pwsh = "error", detail = ex.Message });
        }
    }
}
