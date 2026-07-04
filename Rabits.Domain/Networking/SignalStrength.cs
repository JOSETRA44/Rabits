namespace Rabits.Domain.Networking;

/// <summary>
/// Received signal strength expressed in dBm. Immutable value object that also derives a
/// normalized quality percentage and a 0–4 "bars" indicator for display.
/// </summary>
public readonly record struct SignalStrength : IComparable<SignalStrength>
{
    /// <summary>Signal power in dBm. Typically between -100 (unusable) and -30 (excellent).</summary>
    public int Dbm { get; }

    private SignalStrength(int dbm) => Dbm = dbm;

    public static SignalStrength FromDbm(int dbm) => new(dbm);

    /// <summary>Builds an approximate dBm from a 0–100 link-quality reading (Windows WLAN reports this).</summary>
    public static SignalStrength FromQualityPercent(int quality)
    {
        var clamped = Math.Clamp(quality, 0, 100);
        // Inverse of the common linear mapping: quality = 2 * (dBm + 100).
        return new SignalStrength(clamped / 2 - 100);
    }

    /// <summary>0–100 quality, using the widely-used linear approximation.</summary>
    public int QualityPercent => Math.Clamp(2 * (Dbm + 100), 0, 100);

    /// <summary>Signal bars from 0 (none) to 4 (excellent), suitable for a compact indicator.</summary>
    public int Bars => Dbm switch
    {
        >= -55 => 4,
        >= -66 => 3,
        >= -77 => 2,
        >= -88 => 1,
        _ => 0,
    };

    public int CompareTo(SignalStrength other) => Dbm.CompareTo(other.Dbm);

    public override string ToString() => $"{Dbm} dBm";
}
