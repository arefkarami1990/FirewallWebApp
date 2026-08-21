using System.Text.Json;
using FwGpoWeb.Models;
using FwGpoWeb.Security;

namespace FwGpoWeb.Services;

public sealed class ValidationFailureException : Exception
{
    public ValidationFailureException(string message) : base(message) { }
}

static class JsonExt
{
    // NOTE: member access via ?. / property patterns on Nullable<JsonElement>
    // unwraps to the underlying type, so use explicit .HasValue/.Value.
    public static string? Str(this JsonElement el, string key)
        => el.TryGetProperty(key, out var p) ? p.GetString() : null;

    public static string? Str(this JsonElement? el, string key)
        => (el.HasValue && el.Value.TryGetProperty(key, out var p)) ? p.GetString() : null;

    public static bool? Bool(this JsonElement el, string key)
        => el.TryGetProperty(key, out var p) ? p.GetBoolean() : null;

    public static bool? Bool(this JsonElement? el, string key)
        => (el.HasValue && el.Value.TryGetProperty(key, out var p)) ? p.GetBoolean() : null;

    public static int? Int(this JsonElement el, string key)
        => el.TryGetProperty(key, out var p) && p.ValueKind == JsonValueKind.Number ? p.GetInt32() : null;

    public static int? Int(this JsonElement? el, string key)
        => (el.HasValue && el.Value.TryGetProperty(key, out var p) && p.ValueKind == JsonValueKind.Number) ? p.GetInt32() : null;
}

/// <summary>
/// High-level GPO service: validates input in C# (layer 1), then delegates to
/// the PowerShell/AD layer (layer 2, which re-validates), and verifies the
/// result by reading the rules back.
/// </summary>
public sealed class GpoService
{
    private readonly IPwshBridge _bridge;
    private readonly AuditService _audit;

    public GpoService(IPwshBridge bridge, AuditService audit)
    {
        _bridge = bridge;
        _audit = audit;
    }

    public async Task<DomainInfo> PingDcAsync(string actor, CancellationToken ct)
    {
        var (ok, data, err) = await _bridge.RunAsync("ping-dc", null, ct);
        if (!ok) throw new InvalidOperationException(err ?? "DC ping failed");
        return new DomainInfo(data.Str("domain") ?? "", data.Str("pdc") ?? "", data.Str("serviceUser") ?? "");
    }

    public async Task<List<OuInfo>> ListOusAsync(CancellationToken ct)
    {
        var (ok, data, err) = await _bridge.RunAsync("list-ous", null, ct);
        if (!ok) throw new InvalidOperationException(err ?? "Failed to list OUs");
        var result = new List<OuInfo>();
        if (data.HasValue && data.Value.TryGetProperty("ous", out var ous))
        {
            foreach (var o in ous.EnumerateArray())
                result.Add(new OuInfo(o.Str("name") ?? "", o.Str("dn") ?? ""));
        }
        return result;
    }

    public async Task<List<string>> ListGposAsync(CancellationToken ct)
    {
        var (ok, data, err) = await _bridge.RunAsync("list-gpos", null, ct);
        if (!ok) throw new InvalidOperationException(err ?? "Failed to list GPOs");
        var result = new List<string>();
        if (data.HasValue && data.Value.TryGetProperty("gpos", out var gpos))
        {
            foreach (var e in gpos.EnumerateArray())
            {
                var s = e.GetString();
                if (!string.IsNullOrEmpty(s)) result.Add(s);
            }
        }
        return result;
    }

    public async Task<SearchGpoResult> SearchGpoAsync(SearchGpoRequest req, string actor, CancellationToken ct)
    {
        ValidateCommon(req.OuDn, req.Port, req.PortIsAny, req.Protocol);
        var (ok, data, err) = await _bridge.RunAsync("search-gpo", req, ct);
        if (!ok) throw new ValidationFailureException(err ?? "Search failed");
        var existing = new List<string>();
        if (data.HasValue && data.Value.TryGetProperty("existing", out var ex))
        {
            foreach (var e in ex.EnumerateArray())
            {
                var s = e.GetString();
                if (!string.IsNullOrEmpty(s)) existing.Add(s);
            }
        }
        return new SearchGpoResult
        {
            Found = data.Bool("found") == true,
            GpoName = data.Str("gpoName"),
            Existing = existing.ToArray()
        };
    }

    public async Task<ApplyGpoResult> ApplyGpoAsync(ApplyGpoRequest req, string actor, string ip, CancellationToken ct)
    {
        // ---- layer 1 validation (C#) ----
        ValidateCommon(req.OuDn, req.Port, req.PortIsAny, req.Protocol);
        if (!InputValidator.IsValidMode(req.Mode))
            throw new ValidationFailureException("Invalid mode.");
        if (req.Mode == "specific")
        {
            if (req.Addresses is null || req.Addresses.Length == 0)
                throw new ValidationFailureException("No addresses supplied for mode=specific.");
            if (req.Addresses.Length > 2000)
                throw new ValidationFailureException("Too many addresses (max 2000).");
            var parsed = InputValidator.ParseAddressList(string.Join("\n", req.Addresses));
            if (parsed.Invalid.Length > 0)
                throw new ValidationFailureException($"Invalid entries: {string.Join(", ", parsed.Invalid.Take(20))}");
            if (parsed.Valid.Length == 0)
                throw new ValidationFailureException("No valid IP/CIDR/range entries found.");
            req = req with { Addresses = parsed.Valid };
        }

        await _audit.LogAsync(actor, "GPO_APPLY_START",
            $"ou={req.OuDn} port={(req.PortIsAny ? "Any" : req.Port.ToString())} proto={req.Protocol} mode={req.Mode} count={req.Addresses.Length} blockOthers={req.BlockOthers}",
            true, ip, ct);

        var (ok, data, err) = await _bridge.RunAsync("apply", req, ct);
        if (!ok)
        {
            await _audit.LogAsync(actor, "GPO_APPLY_FAILED", err ?? "unknown error", false, ip, ct);
            throw new ValidationFailureException(err ?? "Apply failed.");
        }

        var log = new List<string>();
        if (data.HasValue && data.Value.TryGetProperty("log", out var logEl))
        {
            foreach (var e in logEl.EnumerateArray())
            {
                var s = e.GetString();
                if (!string.IsNullOrEmpty(s)) log.Add(s);
            }
        }

        var result = new ApplyGpoResult
        {
            GpoName = data.Str("gpoName") ?? "",
            Created = data.Bool("created") == true,
            AllowCount = data.Int("allowCount") ?? 0,
            BlockCount = data.Int("blockCount") ?? 0,
            DeletedOld = data.Int("deletedOld") ?? 0,
            ReadBackAllows = data.Int("readBackAllows") ?? 0,
            ReadBackBlocks = data.Int("readBackBlocks") ?? 0,
            Log = log.ToArray()
        };

        await _audit.LogAsync(actor, "GPO_APPLY_OK",
            $"gpo={result.GpoName} created={result.Created} allows={result.AllowCount} blocks={result.BlockCount} deletedOld={result.DeletedOld}",
            true, ip, ct);
        return result;
    }

    public async Task<(List<GpoRuleInfo> Allows, List<GpoRuleInfo> Blocks)> GetRulesAsync(string gpoName, int port, bool portIsAny, string actor, CancellationToken ct)
    {
        if (!InputValidator.IsValidJsonSafe(gpoName) || !gpoName.All(c => char.IsLetterOrDigit(c) || c is '-' or '_' or '.' or ' '))
            throw new ValidationFailureException("Invalid GPO name.");
        var (ok, data, err) = await _bridge.RunAsync("gpo-rules", new { gpoName, port, portIsAny }, ct);
        if (!ok) throw new ValidationFailureException(err ?? "Failed to read rules");
        List<GpoRuleInfo> Parse(string key)
        {
            var list = new List<GpoRuleInfo>();
            if (data.HasValue && data.Value.TryGetProperty(key, out var arr))
            {
                foreach (var e in arr.EnumerateArray())
                {
                    list.Add(new GpoRuleInfo
                    {
                        Name = e.Str("name") ?? "",
                        Action = e.Str("action") ?? "",
                        Address = e.Str("address") ?? ""
                    });
                }
            }
            return list;
        }
        return (Parse("allows"), Parse("blocks"));
    }

    private static void ValidateCommon(string ouDn, int port, bool portIsAny, string protocol)
    {
        if (!InputValidator.IsValidDn(ouDn))
            throw new ValidationFailureException("Invalid OU DN.");
        if (portIsAny) { if (port != 0) throw new ValidationFailureException("port must be 0 when portIsAny."); }
        else if (port is < 1 or > 65535) throw new ValidationFailureException("Port out of range 1-65535.");
        if (!InputValidator.IsValidProtocol(protocol))
            throw new ValidationFailureException("Invalid protocol (TCP/UDP/Any).");
    }
}
