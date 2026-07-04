namespace Rabits.Domain.Recon;

/// <summary>A subdomain that resolved during enumeration, with the addresses it points to.</summary>
public sealed record Subdomain(string Name, IReadOnlyList<string> Addresses)
{
    public override string ToString() => $"{Name} -> {string.Join(", ", Addresses)}";
}
