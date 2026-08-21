using System.Text.Json;
using FwGpoWeb.Models;

namespace FwGpoWeb.Services;

public interface IAdIdentity
{
    Task<(bool IsAdmin, string? DisplayName)> ResolveAsync(string upn, CancellationToken ct);
}

/// <summary>
/// Identity resolver backed by the PowerShell/AD bridge (same DC path as the
/// GPO operations). .NET 8's System.DirectoryServices.Protocols package does
/// not support LDAP search, so resolution is delegated to the PowerShell
/// module, which uses the ActiveDirectory module on the Windows host.
/// Fails closed: any bridge/AD error => IsAdmin=false.
/// </summary>
public sealed class PwshAdIdentity : IAdIdentity
{
    private readonly IPwshBridge _bridge;
    private readonly string[] _adminGroups;

    public PwshAdIdentity(IPwshBridge bridge, string[] adminGroups)
    {
        _bridge = bridge;
        _adminGroups = adminGroups;
    }

    public async Task<(bool IsAdmin, string? DisplayName)> ResolveAsync(string upn, CancellationToken ct)
    {
        try
        {
            var (ok, data, err) = await _bridge.RunAsync("resolve-user", new { upn, groups = _adminGroups }, ct);
            if (!ok) return (false, null);
            var isAdmin = data.HasValue && data.Value.TryGetProperty("isAdmin", out var a) && a.ValueKind == JsonValueKind.True;
            var name = data.HasValue && data.Value.TryGetProperty("displayName", out var d) ? d.GetString() : null;
            var found = data.HasValue && data.Value.TryGetProperty("found", out var f) && f.ValueKind == JsonValueKind.True;
            return (found && isAdmin, name);
        }
        catch
        {
            return (false, null); // fail closed
        }
    }
}

/// <summary>Mock identity for sandbox/dev (Ad:Mock=true).</summary>
public sealed class MockAdIdentity : IAdIdentity
{
    private readonly bool _mockIsAdmin;

    public MockAdIdentity(string[] adminGroups, bool mockIsAdmin)
    {
        _mockIsAdmin = mockIsAdmin;
    }

    public Task<(bool, string?)> ResolveAsync(string upn, CancellationToken ct)
    {
        var display = upn.Split('@')[0];
        return Task.FromResult((_mockIsAdmin && upn.EndsWith("admin@corp.local", StringComparison.OrdinalIgnoreCase), display));
    }
}
