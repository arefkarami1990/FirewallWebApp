using FwGpoWeb.Auth;
using Xunit;

namespace FwGpoWeb.Tests;

public class LockoutTests
{
    [Fact]
    public void LocksAfterMaxFailures()
    {
        var lo = new LockoutService(maxAttempts: 3, lockMinutes: 5);
        Assert.False(lo.IsLocked("u", out _));
        lo.RegisterFailure("u", out var l1);
        lo.RegisterFailure("u", out var l2);
        Assert.False(l1);
        Assert.False(l2);
        lo.RegisterFailure("u", out var l3);
        Assert.True(l3);
        Assert.True(lo.IsLocked("u", out var rem));
        Assert.True(rem is > 0 and <= 300);
    }

    [Fact]
    public void ResetClears()
    {
        var lo = new LockoutService(2, 5);
        lo.RegisterFailure("u", out _);
        lo.RegisterFailure("u", out _);
        Assert.True(lo.IsLocked("u", out _));
        lo.Reset("u");
        Assert.False(lo.IsLocked("u", out _));
    }

    [Fact]
    public void OtherUsersUnaffected()
    {
        var lo = new LockoutService(1, 5);
        lo.RegisterFailure("a", out _);
        Assert.True(lo.IsLocked("a", out _));
        Assert.False(lo.IsLocked("b", out _));
    }
}
