using System.Net;
using Rabits.Domain.Networking;

namespace Rabits.Application.Abstractions;

/// <summary>Outcome of probing a single host for liveness.</summary>
public sealed record HostProbeResult(HostStatus Status, TimeSpan? Latency, DiscoveryMethod Method)
{
    public static readonly HostProbeResult Down = new(HostStatus.Down, null, DiscoveryMethod.Unknown);
}

/// <summary>Port for determining whether a host is alive (e.g. an ICMP echo request).</summary>
public interface IHostProbe
{
    Task<HostProbeResult> ProbeAsync(IPAddress address, CancellationToken cancellationToken = default);
}
