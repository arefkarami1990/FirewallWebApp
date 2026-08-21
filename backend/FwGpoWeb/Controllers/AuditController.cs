using FwGpoWeb.Services;
using Microsoft.AspNetCore.Mvc;

namespace FwGpoWeb.Controllers;

[ApiController]
[Route("api/audit")]
public class AuditController : Controller
{
    private readonly AuditService _audit;

    public AuditController(AuditService audit) => _audit = audit;

    [HttpGet]
    public async Task<IActionResult> Recent([FromQuery] int limit = 100, CancellationToken ct = default)
    {
        if (limit is < 1 or > 500) limit = 100;
        var entries = await _audit.ReadRecentAsync(limit, ct);
        return Ok(new { entries });
    }
}
