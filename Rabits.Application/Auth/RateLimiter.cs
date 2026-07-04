using System.Diagnostics;

namespace Rabits.Application.Auth;

/// <summary>
/// Simple global rate limiter that keeps calls under a target rate by serializing acquisitions and
/// spacing them by a minimum interval. Used to honour the engagement scope's requests-per-second cap
/// so active audits stay well-behaved (not a flood).
/// </summary>
public sealed class RateLimiter : IDisposable
{
    private readonly double _minIntervalMs;
    private readonly SemaphoreSlim _mutex = new(1, 1);
    private long _lastTimestamp;

    public RateLimiter(int requestsPerSecond)
        => _minIntervalMs = 1000.0 / Math.Max(1, requestsPerSecond);

    public async Task WaitAsync(CancellationToken cancellationToken = default)
    {
        await _mutex.WaitAsync(cancellationToken);
        try
        {
            if (_lastTimestamp != 0)
            {
                var elapsedMs = (Stopwatch.GetTimestamp() - _lastTimestamp) * 1000.0 / Stopwatch.Frequency;
                var remaining = _minIntervalMs - elapsedMs;
                if (remaining > 0)
                    await Task.Delay(TimeSpan.FromMilliseconds(remaining), cancellationToken);
            }
            _lastTimestamp = Stopwatch.GetTimestamp();
        }
        finally
        {
            _mutex.Release();
        }
    }

    public void Dispose() => _mutex.Dispose();
}
