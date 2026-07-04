namespace Rabits.Domain.Traffic;

/// <summary>Coarse protocol classification for a captured frame.</summary>
public enum TrafficProtocol
{
    Other = 0,
    Tcp,
    Udp,
    Icmp,
    IcmpV6,
    Arp,
    Dns,
}

/// <summary>
/// A lightweight, immutable summary of one captured frame. Deliberately holds no raw payload so a
/// high-rate capture stream stays memory-bounded — only the fields needed for live analysis.
/// </summary>
public sealed record CapturedPacket
{
    public required DateTimeOffset Timestamp { get; init; }
    public required int Length { get; init; }
    public required TrafficProtocol Protocol { get; init; }
    public required string Source { get; init; }
    public required string Destination { get; init; }
    public int? SourcePort { get; init; }
    public int? DestinationPort { get; init; }
    public string Info { get; init; } = string.Empty;

    public string SourceEndpoint => SourcePort is { } p ? $"{Source}:{p}" : Source;
    public string DestinationEndpoint => DestinationPort is { } p ? $"{Destination}:{p}" : Destination;
}
