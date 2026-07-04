using System.Net;

namespace Rabits.Domain.Networking;

public enum HostStatus
{
    Unknown = 0,
    Up,
    Down,
}

public enum PortStatus
{
    Open,
    Closed,
    Filtered,
}

/// <summary>How a host's liveness was established.</summary>
public enum DiscoveryMethod
{
    Unknown = 0,
    IcmpEcho,
    ArpProbe,
    TcpProbe,
}

/// <summary>A TCP port observed on a host during discovery.</summary>
public sealed record DiscoveredPort(int Number, PortStatus Status, string? Service = null)
{
    public override string ToString() => Service is null ? Number.ToString() : $"{Number}/{Service}";
}

/// <summary>
/// An immutable snapshot of a single host found during a discovery sweep: its address, liveness,
/// hardware address and resolved vendor, round-trip latency, and any open ports found.
/// </summary>
public sealed record DiscoveredHost
{
    public required IPAddress Address { get; init; }
    public required HostStatus Status { get; init; }
    public DiscoveryMethod Method { get; init; } = DiscoveryMethod.Unknown;
    public MacAddress? Mac { get; init; }
    public string? Vendor { get; init; }
    public string? Hostname { get; init; }
    public TimeSpan? Latency { get; init; }
    public IReadOnlyList<DiscoveredPort> OpenPorts { get; init; } = Array.Empty<DiscoveredPort>();

    public bool IsUp => Status == HostStatus.Up;

    /// <summary>Sortable numeric form of an IPv4 address (0 for non-IPv4), for stable ordering.</summary>
    public uint AddressSortKey
    {
        get
        {
            var b = Address.GetAddressBytes();
            return b.Length == 4
                ? ((uint)b[0] << 24) | ((uint)b[1] << 16) | ((uint)b[2] << 8) | b[3]
                : 0u;
        }
    }
}
