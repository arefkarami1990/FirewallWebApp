using System.Text.Json;
using FwGpoWeb.Models;
using FwGpoWeb.Services;
using Xunit;

namespace FwGpoWeb.Tests;

/// <summary>Fake bridge capturing calls (no process spawn).</summary>
public sealed class FakePwshBridge : IPwshBridge
{
    public List<(string Op, object? Params)> Calls { get; } = new();
    public Func<string, object?, PwshResult> Handler { get; set; } = (op, p) =>
        new PwshResult(false, null, "no handler");

    public Task<PwshResult> RunAsync(string op, object? parameters, CancellationToken ct)
    {
        Calls.Add((op, parameters));
        return Task.FromResult(Handler(op, parameters));
    }
}

public class GpoServiceTests
{
    private static (GpoService Svc, FakePwshBridge Bridge, AuditService Audit) Build()
    {
        var dir = Path.Combine(Path.GetTempPath(), "fwgpoweb-test-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        var audit = new AuditService(dir);
        var bridge = new FakePwshBridge();
        var svc = new GpoService(bridge, audit);
        return (svc, bridge, audit);
    }

    [Fact]
    public async Task ApplyRejectsInvalidIpBeforeBridge()
    {
        var (svc, bridge, _) = Build();
        var req = new ApplyGpoRequest
        {
            OuDn = "OU=Servers,DC=corp,DC=local",
            Port = 3389,
            Protocol = "TCP",
            Mode = "specific",
            Addresses = new[] { "1.2.3.4; rm -rf /", "garbage" }
        };
        await Assert.ThrowsAsync<ValidationFailureException>(() => svc.ApplyGpoAsync(req, "a@b.c", "1.1.1.1", CancellationToken.None));
        Assert.Empty(bridge.Calls); // nothing reached the bridge
    }

    [Fact]
    public async Task ApplyRejectsBadDn()
    {
        var (svc, bridge, _) = Build();
        var req = new ApplyGpoRequest
        {
            OuDn = "C:\\Windows\\System32",
            Port = 3389,
            Mode = "any"
        };
        await Assert.ThrowsAsync<ValidationFailureException>(() => svc.ApplyGpoAsync(req, "a@b.c", "1.1.1.1", CancellationToken.None));
        Assert.Empty(bridge.Calls);
    }

    [Fact]
    public async Task ApplyNormalizesAndSendsValidAddresses()
    {
        var (svc, bridge, _) = Build();
        bridge.Handler = (op, p) =>
        {
            Assert.Equal("apply", op);
            var req = (ApplyGpoRequest)JsonSerializer.Deserialize<ApplyGpoRequest>(JsonSerializer.Serialize(p), new JsonSerializerOptions(JsonSerializerDefaults.Web))!;
            Assert.Equal(new[] { "10.0.0.5", "10.1.0.0/24" }, req.Addresses);
            return new PwshResult(true,
                JsonSerializer.SerializeToElement(new { gpoName = "Servers-Access-3389-TCP-ADD", created = true, allowCount = 2, blockCount = 3, deletedOld = 1, readBackAllows = 2, readBackBlocks = 3, log = new[] { "ok" } }),
                null);
        };
        var req = new ApplyGpoRequest
        {
            OuDn = "OU=Servers,DC=corp,DC=local",
            Port = 3389,
            Protocol = "TCP",
            Mode = "specific",
            Addresses = new[] { "10.0.0.5", "10.1.0.0/24", "  " }
        };
        var result = await svc.ApplyGpoAsync(req, "admin@corp.local", "10.0.0.1", CancellationToken.None);
        Assert.Equal("Servers-Access-3389-TCP-ADD", result.GpoName);
        Assert.Equal(2, result.AllowCount);
        Assert.Equal(3, result.BlockCount);
        Assert.True(result.Created);
    }

    [Fact]
    public async Task SearchReturnsExistingIps()
    {
        var (svc, bridge, _) = Build();
        bridge.Handler = (op, p) => new PwshResult(true,
            JsonSerializer.SerializeToElement(new { found = true, gpoName = "Servers-Access-3389-TCP-ADD", existing = new[] { "10.10.0.5", "10.20.0.0/24" } }), null);
        var r = await svc.SearchGpoAsync(new SearchGpoRequest { OuDn = "OU=Servers,DC=corp,DC=local", Port = 3389, Protocol = "TCP" }, "a@b.c", CancellationToken.None);
        Assert.True(r.Found);
        Assert.Equal(2, r.Existing.Length);
    }

    [Fact]
    public async Task RulesParsesAllowBlock()
    {
        var (svc, bridge, _) = Build();
        bridge.Handler = (op, p) => new PwshResult(true,
            JsonSerializer.SerializeToElement(new
            {
                allows = new[] { new { name = "a1", action = "Allow", address = "10.0.0.5" } },
                blocks = new[] { new { name = "b1", action = "Block", address = "0.0.0.0-10.0.0.4" } }
            }), null);
        var (allows, blocks) = await svc.GetRulesAsync("Servers-Access-3389-TCP-ADD", 3389, false, "a@b.c", CancellationToken.None);
        Assert.Single(allows);
        Assert.Equal("10.0.0.5", allows[0].Address);
        Assert.Single(blocks);
    }

    [Fact]
    public async Task PortRangeEnforced()
    {
        var (svc, bridge, _) = Build();
        await Assert.ThrowsAsync<ValidationFailureException>(() =>
            svc.SearchGpoAsync(new SearchGpoRequest { OuDn = "OU=Servers,DC=corp,DC=local", Port = 70000, Protocol = "TCP" }, "a@b.c", CancellationToken.None));
        await Assert.ThrowsAsync<ValidationFailureException>(() =>
            svc.SearchGpoAsync(new SearchGpoRequest { OuDn = "OU=Servers,DC=corp,DC=local", Port = 3389, Protocol = "ICMP" }, "a@b.c", CancellationToken.None));
    }
}
