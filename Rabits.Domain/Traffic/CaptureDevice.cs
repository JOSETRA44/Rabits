namespace Rabits.Domain.Traffic;

/// <summary>A network interface available for packet capture.</summary>
public sealed record CaptureDevice(string Id, string Name, string Description)
{
    public override string ToString() => string.IsNullOrWhiteSpace(Description) ? Name : Description;
}
