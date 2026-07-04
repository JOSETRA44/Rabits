namespace Rabits.Application.Traffic;

/// <summary>Parameters for a capture session.</summary>
public sealed record CaptureRequest
{
    /// <summary>Device id to capture on; null selects the first available device.</summary>
    public string? DeviceId { get; init; }

    /// <summary>Optional Berkeley Packet Filter expression (e.g. "tcp port 443").</summary>
    public string? BpfFilter { get; init; }

    public bool Promiscuous { get; init; } = true;

    public int SnapLength { get; init; } = 65536;
}
