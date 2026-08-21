using System.Text.Json;

namespace FwGpoWeb.Services;

/// <summary>
/// Append-only JSON-lines audit log under %ProgramData%/FwGpoWeb/audit (or
/// DataDir/audit). Every security-relevant event is recorded: login, MFA
/// success/failure, lockouts, FIDO register/verify, GPO search/apply, admin
/// queries. On Windows, events are also written to the Application event log
/// channel "FwGpoWeb".
/// </summary>
public sealed class AuditService
{
    private readonly string _dir;
    private readonly SemaphoreSlim _gate = new(1, 1);
    private static readonly JsonSerializerOptions Opts = new(JsonSerializerDefaults.Web)
    {
        WriteIndented = false
    };

    public AuditService(string dataDir)
    {
        _dir = Path.Combine(dataDir, "audit");
        Directory.CreateDirectory(_dir);
    }

    public async Task LogAsync(string actor, string action, string details, bool success, string ip, CancellationToken ct = default)
    {
        var entry = new Models.AuditEntry
        {
            Ts = DateTimeOffset.UtcNow,
            Actor = Truncate(actor, 200),
            Action = Truncate(action, 100),
            Details = Truncate(details, 2000),
            Success = success,
            Ip = ip
        };
        var json = JsonSerializer.Serialize(entry, Opts);
        await _gate.WaitAsync(ct);
        try
        {
            var file = Path.Combine(_dir, $"audit-{DateTime.UtcNow:yyyyMMdd}.jsonl");
            await using var fs = new FileStream(file, FileMode.Append, FileAccess.Write, FileShare.Read);
            await fs.WriteAsync(System.Text.Encoding.UTF8.GetBytes(json + Environment.NewLine), ct);
        }
        finally
        {
            _gate.Release();
        }
        WriteEventLog(entry);
    }

    public async Task<List<Models.AuditEntry>> ReadRecentAsync(int limit, CancellationToken ct = default)
    {
        var result = new List<Models.AuditEntry>();
        if (!Directory.Exists(_dir)) return result;
        var files = Directory.GetFiles(_dir, "audit-*.jsonl").OrderByDescending(f => f).Take(3);
        foreach (var f in files)
        {
            var lines = await File.ReadAllLinesAsync(f, ct);
            for (int i = lines.Length - 1; i >= 0 && result.Count < limit; i--)
            {
                try { result.Add(JsonSerializer.Deserialize<Models.AuditEntry>(lines[i], Opts)!); }
                catch { }
            }
            if (result.Count >= limit) break;
        }
        return result;
    }

    private static string Truncate(string s, int max) => string.IsNullOrEmpty(s) ? "" : (s.Length <= max ? s : s[..max] + "...");

    private static void WriteEventLog(Models.AuditEntry e)
    {
        if (!OperatingSystem.IsWindows()) return;
        try
        {
            if (!System.Diagnostics.EventLog.SourceExists("FwGpoWeb"))
            {
                try { System.Diagnostics.EventLog.CreateEventSource("FwGpoWeb", "Application"); } catch { }
            }
            using var log = new System.Diagnostics.EventLog("Application", ".", "FwGpoWeb");
            var type = e.Success ? System.Diagnostics.EventLogEntryType.Information : System.Diagnostics.EventLogEntryType.Warning;
            log.WriteEntry($"[{e.Action}] {e.Actor} :: {e.Details}", type);
        }
        catch { /* best effort */ }
    }
}
