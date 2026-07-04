namespace Rabits.Application.Hosts;

/// <summary>Parameters for a host discovery sweep.</summary>
public sealed record HostDiscoveryRequest
{
    /// <summary>Target as CIDR ("10.0.0.0/24") or a single IP.</summary>
    public required string Target { get; init; }

    public PortScanProfile Ports { get; init; } = PortScanProfile.None;

    /// <summary>Maximum simultaneous host probes.</summary>
    public int Concurrency { get; init; } = 64;

    public bool ResolveMac { get; init; } = true;

    public bool ResolveHostname { get; init; }

    /// <summary>Upper bound on the number of hosts expanded from the target (safety cap).</summary>
    public int MaxHosts { get; init; } = 4096;
}
