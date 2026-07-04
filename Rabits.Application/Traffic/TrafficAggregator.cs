using System.Diagnostics;
using Rabits.Domain.Traffic;

namespace Rabits.Application.Traffic;

/// <summary>
/// Thread-safe live counters for a capture stream. A capture consumer calls <see cref="Add"/> from
/// any thread; UI/CLI poll <see cref="Snapshot"/> on a timer. Uses interlocked primitives only, so
/// it never blocks the capture thread and holds no packet references (no leak under high volume).
/// </summary>
public sealed class TrafficAggregator
{
    private static readonly int ProtocolCount = Enum.GetValues<TrafficProtocol>().Length;

    private readonly long[] _byProtocol = new long[ProtocolCount];
    private long _totalPackets;
    private long _totalBytes;
    private long _startTimestamp;

    public void Add(CapturedPacket packet)
    {
        Interlocked.CompareExchange(ref _startTimestamp, Stopwatch.GetTimestamp(), 0);
        Interlocked.Increment(ref _totalPackets);
        Interlocked.Add(ref _totalBytes, packet.Length);

        var index = (int)packet.Protocol;
        if ((uint)index < (uint)_byProtocol.Length)
            Interlocked.Increment(ref _byProtocol[index]);
    }

    public TrafficStatistics Snapshot()
    {
        var packets = Interlocked.Read(ref _totalPackets);
        var bytes = Interlocked.Read(ref _totalBytes);
        var start = Interlocked.Read(ref _startTimestamp);

        var elapsedSeconds = start == 0
            ? 0
            : (Stopwatch.GetTimestamp() - start) / (double)Stopwatch.Frequency;

        var byProtocol = new Dictionary<TrafficProtocol, long>();
        foreach (var protocol in Enum.GetValues<TrafficProtocol>())
        {
            var count = Interlocked.Read(ref _byProtocol[(int)protocol]);
            if (count > 0) byProtocol[protocol] = count;
        }

        return new TrafficStatistics
        {
            TotalPackets = packets,
            TotalBytes = bytes,
            PacketsPerSecond = elapsedSeconds > 0 ? packets / elapsedSeconds : 0,
            ByProtocol = byProtocol,
        };
    }

    public void Reset()
    {
        Interlocked.Exchange(ref _totalPackets, 0);
        Interlocked.Exchange(ref _totalBytes, 0);
        Interlocked.Exchange(ref _startTimestamp, 0);
        for (var i = 0; i < _byProtocol.Length; i++)
            Interlocked.Exchange(ref _byProtocol[i], 0);
    }
}
