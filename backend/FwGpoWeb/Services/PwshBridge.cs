using System.Diagnostics;
using System.Security.AccessControl;
using System.Text.Json;
using FwGpoWeb.Models;

namespace FwGpoWeb.Services;

public sealed record PwshResult(bool Ok, JsonElement? Data, string? Error);

public interface IPwshBridge
{
    /// <summary>Runs a named operation; Data is null on error.</summary>
    Task<PwshResult> RunAsync(string op, object? parameters, CancellationToken ct);
}

public sealed record PwshConfig(string Exe, string ModuleDir, int TimeoutSeconds);

/// <summary>
/// Out-of-process PowerShell bridge.
/// Security properties:
///  - user input is transferred ONLY via a JSON request file (never on the
///    command line) -> no shell/command-line injection surface
///  - fixed ArgumentList (no string interpolation), -NoProfile -NonInteractive
///  - hard timeout, temp files created in a restricted directory and deleted after
///  - response is parsed as JSON; any failure surfaces as Ok=false + Error
/// </summary>
public sealed class PwshBridge : IPwshBridge
{
    private static readonly JsonSerializerOptions JsonOpts = new(JsonSerializerDefaults.Web)
    {
        Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping
    };

    private readonly PwshConfig _cfg;
    private readonly string _tmpDir;

    public PwshBridge(PwshConfig cfg, string dataDir)
    {
        _cfg = cfg;
        _tmpDir = Path.Combine(dataDir, "pwsh-tmp");
        Directory.CreateDirectory(_tmpDir);
        RestrictAcls(_tmpDir);
    }

    private static void RestrictAcls(string dir)
    {
        if (!OperatingSystem.IsWindows()) return;
        try
        {
            var sd = new DirectorySecurity();
            var identity = System.Security.Principal.WindowsIdentity.GetCurrent();
            sd.AddAccessRule(new FileSystemAccessRule(identity.Name,
                FileSystemRights.FullControl, AccessControlType.Allow));
            sd.AddAccessRule(new FileSystemAccessRule("BUILTIN\\Administrators",
                FileSystemRights.FullControl, AccessControlType.Allow));
            new DirectoryInfo(dir).SetAccessControl(sd);
        }
        catch { /* best effort */ }
    }

    public async Task<PwshResult> RunAsync(string op, object? parameters, CancellationToken ct)
    {
        var reqFile = Path.Combine(_tmpDir, $"req_{Guid.NewGuid():N}.json");
        var respFile = Path.Combine(_tmpDir, $"resp_{Guid.NewGuid():N}.json");
        var psi = new ProcessStartInfo
        {
            FileName = _cfg.Exe,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true
        };
        psi.ArgumentList.Add("-NoProfile");
        psi.ArgumentList.Add("-NonInteractive");
        psi.ArgumentList.Add("-ExecutionPolicy");
        psi.ArgumentList.Add("Bypass");
        psi.ArgumentList.Add("-File");
        psi.ArgumentList.Add(Path.Combine(_cfg.ModuleDir, "Invoke-FwGpoOp.ps1"));
        psi.ArgumentList.Add("-RequestFile");
        psi.ArgumentList.Add(reqFile);
        psi.ArgumentList.Add("-ResponseFile");
        psi.ArgumentList.Add(respFile);

        var req = new { op = op, parameters };
        await File.WriteAllTextAsync(reqFile, JsonSerializer.Serialize(req, JsonOpts), ct);

        try
        {
            using var proc = new Process { StartInfo = psi };
            proc.Start();
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            cts.CancelAfter(TimeSpan.FromSeconds(_cfg.TimeoutSeconds));
            try
            {
                await proc.WaitForExitAsync(cts.Token);
            }
            catch (OperationCanceledException)
            {
                try { proc.Kill(entireProcessTree: true); } catch { }
                return new PwshResult(false, null, "PowerShell operation timed out.");
            }
            if (!File.Exists(respFile))
            {
                var stderr = await proc.StandardError.ReadToEndAsync();
                return new PwshResult(false, null, string.IsNullOrWhiteSpace(stderr)
                    ? $"PowerShell exited with code {proc.ExitCode}."
                    : "PowerShell failed (see server log).");
            }
            var text = await File.ReadAllTextAsync(respFile);
            using var doc = JsonDocument.Parse(text);
            var root = doc.RootElement;
            if (root.TryGetProperty("ok", out var okEl) && okEl.ValueKind == JsonValueKind.True)
            {
                JsonElement? dataEl = null;
                if (root.TryGetProperty("data", out var d)) dataEl = d.Clone();
                return new PwshResult(true, dataEl, null);
            }
            var errMsg = root.TryGetProperty("error", out var e) ? e.GetString() : "Unknown PowerShell error.";
            return new PwshResult(false, null, errMsg);
        }
        finally
        {
            TryDelete(reqFile);
            TryDelete(respFile);
        }
    }

    private static void TryDelete(string p)
    {
        try { if (File.Exists(p)) File.Delete(p); } catch { }
    }
}
