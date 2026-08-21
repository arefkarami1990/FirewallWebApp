using System.Collections.Concurrent;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace FwGpoWeb.Services;

static class NodeExt
{
    public static int? GetInt(this JsonNode? n)
    {
        if (n is null) return null;
        var je = JsonSerializer.SerializeToElement(n);
        return je.ValueKind == JsonValueKind.Number ? je.GetInt32() : null;
    }

    public static bool? GetBool(this JsonNode? n)
    {
        if (n is null) return null;
        var je = JsonSerializer.SerializeToElement(n);
        return je.ValueKind switch { JsonValueKind.True => true, JsonValueKind.False => false, _ => null };
    }

    public static string? GetStr(this JsonNode? n)
    {
        if (n is null) return null;
        var je = JsonSerializer.SerializeToElement(n);
        return je.ValueKind == JsonValueKind.String ? je.GetString() : null;
    }
}

/// <summary>
/// In-memory mock of the PowerShell/AD layer. Used ONLY when Ad:Mock=true
/// (development and sandbox testing). It emulates a small domain so the whole
/// web stack (auth, MFA, FIDO2, GPO flows) can be exercised end-to-end
/// without a Windows/AD environment.
/// </summary>
public sealed class MockPwshBridge : IPwshBridge
{
    private static readonly (string Name, string Dn)[] Ous =
    {
        ("Servers", "OU=Servers,DC=corp,DC=local"),
        ("Workstations", "OU=Workstations,DC=corp,DC=local"),
        ("Apps", "OU=Apps,DC=corp,DC=local"),
        ("RDP Targets", "OU=RDP Targets,OU=Servers,DC=corp,DC=local"),
    };

    private sealed record GpoState(string Name, string OuDn, Dictionary<string, JsonNode> Rules);

    private readonly ConcurrentDictionary<string, GpoState> _gpos = new(StringComparer.OrdinalIgnoreCase);
    private readonly object _gate = new();

    public MockPwshBridge()
    {
        var seed = new GpoState("Servers-Access-3389-TCP-ADD", Ous[0].Dn, new());
        seed.Rules["Allow-FW-TCP-3389-Approved-0"] = new JsonObject
        {
            ["name"] = "Allow-FW-TCP-3389-Approved-0",
            ["value"] = "v2.30|Action=Allow|Active=TRUE|Dir=In|Protocol=6|LPort=3389|RA4=10.10.0.5|Name=Allow TCP 3389 from 10.10.0.5|Desc=ADD|EmbedCtxt=FW-ADD|"
        };
        _gpos[seed.Name] = seed;
    }

    public Task<PwshResult> RunAsync(string op, object? parameters, CancellationToken ct)
    {
        try
        {
            var p = parameters is null ? new JsonObject() : JsonSerializer.SerializeToNode(parameters);
            switch (op)
            {
                case "ping-dc":
                    return Ok(new { domain = "corp.local", pdc = "dc1.corp.local", serviceUser = "MACHINE\\fwgpowsrv$" });
                case "whoami":
                    return Ok(new { identity = "MACHINE\\fwgpowsrv$", isDomainAdmin = true });
                case "resolve-user":
                {
                    var upn = p?["upn"].GetStr() ?? "";
                    return Ok(new
                    {
                        found = upn.EndsWith("admin@corp.local", StringComparison.OrdinalIgnoreCase) || upn.Length > 0,
                        displayName = upn.Split('@')[0],
                        isAdmin = upn.EndsWith("admin@corp.local", StringComparison.OrdinalIgnoreCase)
                    });
                }
                case "list-ous":
                    return Ok(new { ous = Ous.Select(o => new { name = o.Name, dn = o.Dn }) });
                case "test-ou":
                {
                    var dn = p?["dn"].GetStr();
                    return Ok(new { exists = Ous.Any(o => string.Equals(o.Dn, dn, StringComparison.OrdinalIgnoreCase)) });
                }
                case "list-gpos":
                    lock (_gate) return Ok(new { gpos = _gpos.Keys.OrderBy(x => x).ToArray() });
                case "search-gpo":
                    return SearchGpo(p);
                case "gpo-rules":
                    return GpoRules(p);
                case "apply":
                    return Apply(p);
                default:
                    return Err($"unknown op {op}");
            }
        }
        catch (Exception ex)
        {
            return Err(ex.Message);
        }
    }

    private Task<PwshResult> Ok(object o) => Task.FromResult(new PwshResult(true, JsonSerializer.SerializeToElement(o), null));
    private Task<PwshResult> Err(string e) => Task.FromResult(new PwshResult(false, null, e));

    private Task<PwshResult> SearchGpo(JsonNode? p)
    {
        var ouDn = p?["ouDn"].GetStr();
        var port = p?["port"].GetInt() ?? 0;
        var portIsAny = p?["portIsAny"].GetBool() ?? false;
        var proto = p?["protocol"].GetStr() ?? "TCP";
        if (string.IsNullOrWhiteSpace(ouDn)) return Err("ouDn is required.");
        if (!Ous.Any(o => string.Equals(o.Dn, ouDn, StringComparison.OrdinalIgnoreCase))) return Err($"OU not found: {ouDn}");
        var token = portIsAny ? "Any" : port.ToString();
        lock (_gate)
        {
            var found = _gpos.FirstOrDefault(g =>
                g.Value.OuDn == ouDn && g.Key.Contains(token) && GpoMatchesProto(g.Key, proto)).Key;
            if (found is null) return Ok(new { found = false, gpoName = (string?)null, existing = Array.Empty<string>() });
            var existing = new List<string>();
            foreach (var r in _gpos[found].Rules.Values)
            {
                var v = r["value"].GetStr();
                if (v is null || !v.Contains("Action=Allow")) continue;
                if (!GpoValueMatchesPort(v, port, portIsAny)) continue;
                if (!GpoValueMatchesProto(v, proto)) continue;
                var m = System.Text.RegularExpressions.Regex.Match(v, @"\|RA4=([^|]+)\|");
                if (m.Success)
                    foreach (var ra in m.Groups[1].Value.Split(','))
                    {
                        var bare = ra.Contains('/') ? ra[..ra.IndexOf('/')] : ra;
                        if (!existing.Contains(bare)) existing.Add(bare);
                    }
            }
            return Ok(new { found = true, gpoName = found, existing = existing.ToArray() });
        }
    }

    private static bool GpoMatchesProto(string name, string proto)
        => proto == "Any" ? name.Contains("-TCP-") || name.Contains("-UDP-") : name.Contains($"-{proto}-");

    private static bool GpoValueMatchesProto(string v, string proto)
        => proto == "Any" ? v.Contains("Protocol=6|") || v.Contains("Protocol=17|")
           : proto == "TCP" ? v.Contains("Protocol=6|")
           : v.Contains("Protocol=17|");

    private static bool GpoValueMatchesPort(string v, int port, bool portIsAny)
    {
        if (portIsAny)
        {
            if (v.Contains("LPort="))
            {
                var m = System.Text.RegularExpressions.Regex.Match(v, @"LPort=(\d+|\*)\|");
                return m.Success && (m.Groups[1].Value == "0" || m.Groups[1].Value == "*");
            }
            return true;
        }
        return v.Contains($"LPort={port}|");
    }

    private Task<PwshResult> GpoRules(JsonNode? p)
    {
        var gpoName = p?["gpoName"].GetStr();
        var port = p?["port"].GetInt() ?? 0;
        var portIsAny = p?["portIsAny"].GetBool() ?? false;
        lock (_gate)
        {
            if (!_gpos.TryGetValue(gpoName ?? "", out var g)) return Err($"GPO not found: {gpoName}");
            var allows = new List<JsonObject>();
            var blocks = new List<JsonObject>();
            foreach (var kv in g.Rules)
            {
                var v = kv.Value["value"].GetStr() ?? "";
                if (!GpoValueMatchesPort(v, port, portIsAny)) continue;
                var m = System.Text.RegularExpressions.Regex.Match(v, @"\|RA4=([^|]+)\|");
                var isAllow = v.Contains("Action=Allow");
                var target = isAllow ? allows : blocks;
                target.Add(new JsonObject
                {
                    ["name"] = kv.Value["name"].GetStr() ?? kv.Key,
                    ["action"] = isAllow ? "Allow" : "Block",
                    ["address"] = m.Success ? m.Groups[1].Value : ""
                });
            }
            return Ok(new { allows, blocks });
        }
    }

    private Task<PwshResult> Apply(JsonNode? p)
    {
        var ouDn = p?["ouDn"].GetStr();
        var port = p?["port"].GetInt() ?? 0;
        var portIsAny = p?["portIsAny"].GetBool() ?? false;
        var proto = p?["protocol"].GetStr() ?? "TCP";
        var mode = p?["mode"].GetStr() ?? "specific";
        var addrs = p?["addresses"] is { } arr
            ? arr.AsArray().Select(x => x.GetStr()).Where(x => x != null).Cast<string>().ToArray()
            : Array.Empty<string>();
        if (string.IsNullOrWhiteSpace(ouDn)) return Err("ouDn is required.");
        if (!Ous.Any(o => string.Equals(o.Dn, ouDn, StringComparison.OrdinalIgnoreCase))) return Err($"OU not found: {ouDn}");
        if (proto is not ("TCP" or "UDP" or "Any")) return Err($"Invalid protocol '{proto}'.");
        if (mode is not ("specific" or "any" or "localsubnet")) return Err($"Invalid mode '{mode}'.");
        if (!portIsAny && (port < 1 || port > 65535)) return Err("Port out of range 1-65535.");
        if (mode == "specific" && addrs.Length == 0) return Err("No addresses supplied for mode=specific.");

        var token = portIsAny ? "Any" : port.ToString();
        var action = mode switch { "any" => "ANY", "localsubnet" => "BLOCK-LOCALSUBNET", _ => "ADD" };
        var shortOu = ouDn.Split(',')[0].Split('=')[1];
        var protoShort = proto switch { "TCP" => "TCP", "UDP" => "UDP", _ => "Any" };
        var gpoName = $"{shortOu}-Access-{token}-{protoShort}-{action}".Replace('\\', '_');

        lock (_gate)
        {
            var created = false;
            if (!_gpos.TryGetValue(gpoName, out var g))
            {
                g = new GpoState(gpoName, ouDn, new());
                _gpos[gpoName] = g;
                created = true;
            }
            int deleted = 0;
            foreach (var kv in g.Rules.ToArray())
            {
                if (GpoValueMatchesPort(kv.Value["value"].GetStr() ?? "", port, portIsAny))
                {
                    g.Rules.Remove(kv.Key);
                    deleted++;
                }
            }
            var log = new List<string> { $"Mock apply: {gpoName}" };
            int allowCount = 0, blockCount = 0;
            var lport = portIsAny ? "" : $"LPort={port}|";
            var protos = new List<(string Name, int Num)>();
            if (proto is "TCP" or "Any") protos.Add(("TCP", 6));
            if (proto is "UDP" or "Any") protos.Add(("UDP", 17));

            if (mode == "specific")
            {
                foreach (var pr in protos)
                {
                    for (int i = 0; i < addrs.Length; i++)
                    {
                        var name = $"Allow-FW-{pr.Name}-{token}-Approved-{i}";
                        g.Rules[name] = new JsonObject
                        {
                            ["name"] = name,
                            ["value"] = $"v2.30|Action=Allow|Active=TRUE|Dir=In|Protocol={pr.Num}|{lport}RA4={addrs[i]}|Name=Allow {pr.Name} {token} from {addrs[i]}|Desc=ADD|EmbedCtxt=FW-ADD|"
                        };
                        allowCount++;
                    }
                }
                if (proto is "TCP" or "Any")
                {
                    var name = "Block-FW-TCP-Except-0";
                    g.Rules[name] = new JsonObject
                    {
                        ["name"] = name,
                        ["value"] = $"v2.30|Action=Block|Active=TRUE|Dir=In|Protocol=6|{lport}RA4=0.0.0.0-255.255.255.255|Name=Block TCP {token}|Desc=Block all except allowed|EmbedCtxt=FW-ADD-Block|"
                    };
                    blockCount++;
                }
                log.Add("Mock: allow + block complement written (mock complement is representative)");
            }
            else if (mode == "any")
            {
                foreach (var pr in protos)
                {
                    var name = $"Allow-FW-{pr.Name}-{token}-Any";
                    g.Rules[name] = new JsonObject
                    {
                        ["name"] = name,
                        ["value"] = $"v2.30|Action=Allow|Active=TRUE|Dir=In|Protocol={pr.Num}|{lport}RA4=Any|Name=Allow {pr.Name} {token} Any|Desc=Any|EmbedCtxt=FW-ANY|"
                    };
                    allowCount++;
                }
            }
            else
            {
                foreach (var pr in protos)
                {
                    var name = $"Block-FW-{pr.Name}-{token}-LocalSubnet";
                    g.Rules[name] = new JsonObject
                    {
                        ["name"] = name,
                        ["value"] = $"v2.30|Action=Block|Active=TRUE|Dir=In|Protocol={pr.Num}|{lport}RA4=LocalSubnet|Name=Block {pr.Name} {token} LocalSubnet|Desc=Block LocalSubnet|EmbedCtxt=FW-BLOCK-LOCAL|"
                    };
                    blockCount++;
                }
            }

            log.Add("Mock verification pass complete");
            return Ok(new
            {
                gpoName,
                created,
                allowCount,
                blockCount,
                deletedOld = deleted,
                readBackAllows = allowCount,
                readBackBlocks = blockCount,
                log = log.ToArray()
            });
        }
    }
}
