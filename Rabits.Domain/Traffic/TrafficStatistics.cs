namespace Rabits.Domain.Traffic;

/// <summary>An immutable snapshot of live capture counters.</summary>
public sealed record TrafficStatistics
{
    public required long TotalPackets { get; init; }
    public required long TotalBytes { get; init; }
    public required double PacketsPerSecond { get; init; }
    public IReadOnlyDictionary<TrafficProtocol, long> ByProtocol { get; init; }
        = new Dictionary<TrafficProtocol, long>();

    public static readonly TrafficStatistics Empty = new() { TotalPackets = 0, TotalBytes = 0, PacketsPerSecond = 0 };

    public long CountOf(TrafficProtocol protocol) => ByProtocol.TryGetValue(protocol, out var c) ? c : 0;
}
