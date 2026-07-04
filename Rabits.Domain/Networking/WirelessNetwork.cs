namespace Rabits.Domain.Networking;

/// <summary>
/// An immutable snapshot of a single wireless network (one BSS) observed during a scan.
/// This is a passive-recon observation: it describes what was seen on the air, nothing more.
/// </summary>
public sealed record WirelessNetwork
{
    public required string Ssid { get; init; }
    public required MacAddress Bssid { get; init; }
    public required SignalStrength Rssi { get; init; }
    public required NetworkChannel Channel { get; init; }
    public required EncryptionType Encryption { get; init; }

    /// <summary>Raw capability/auth string as reported by the adapter (e.g. "WPA2-PSK-CCMP").</summary>
    public string Capabilities { get; init; } = string.Empty;

    /// <summary>True when the network advertises no link-layer encryption.</summary>
    public bool IsOpen => Encryption == EncryptionType.Open;

    /// <summary>A hidden network broadcasts an empty SSID.</summary>
    public bool IsHidden => string.IsNullOrEmpty(Ssid);

    public string DisplaySsid => IsHidden ? "<hidden>" : Ssid;
}
