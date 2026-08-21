using System.Collections.Concurrent;

namespace FwGpoWeb.Auth;

/// <summary>
/// In-memory MFA lockout: after N failed MFA attempts for a UPN, lock for
/// M minutes. Every failure/success is also written to the audit log by the
/// caller.
/// </summary>
public sealed class LockoutService
{
    private readonly ConcurrentDictionary<string, (int Fails, DateTime LockUntilUtc)> _state = new();
    private readonly int _maxAttempts;
    private readonly TimeSpan _lockSpan;

    public LockoutService(int maxAttempts = 5, int lockMinutes = 15)
    {
        _maxAttempts = maxAttempts;
        _lockSpan = TimeSpan.FromMinutes(lockMinutes);
    }

    public bool IsLocked(string upn, out int remainingSeconds)
    {
        // NOTE: the entry is deliberately NOT removed when the lock expires —
        // the failure count must survive between requests (an entry with
        // LockUntilUtc in the past simply means "not locked right now").
        remainingSeconds = 0;
        if (_state.TryGetValue(upn, out var s) && s.LockUntilUtc > DateTime.UtcNow)
        {
            remainingSeconds = (int)(s.LockUntilUtc - DateTime.UtcNow).TotalSeconds + 1;
            return true;
        }
        return false;
    }

    public bool RegisterFailure(string upn, out bool nowLocked)
    {
        nowLocked = false;
        // Until the threshold is reached LockUntilUtc stays in the past
        // ("not locked"); the failure count accumulates across requests.
        var s = _state.AddOrUpdate(upn,
            _ => (1, DateTime.MinValue),
            (_, cur) => (cur.Fails + 1, cur.LockUntilUtc));
        if (s.Fails >= _maxAttempts && s.LockUntilUtc <= DateTime.UtcNow)
        {
            s = (s.Fails, DateTime.UtcNow.Add(_lockSpan));
            _state[upn] = s;
            nowLocked = true;
        }
        return nowLocked;
    }

    public void Reset(string upn) => _state.TryRemove(upn, out _);
}
