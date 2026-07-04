namespace Rabits.Domain.Recon;

/// <summary>Summary of the X.509 certificate presented by an HTTPS endpoint.</summary>
public sealed record TlsCertificateInfo
{
    public required string Subject { get; init; }
    public required string Issuer { get; init; }
    public required DateTimeOffset NotBefore { get; init; }
    public required DateTimeOffset NotAfter { get; init; }
    public IReadOnlyList<string> SubjectAltNames { get; init; } = Array.Empty<string>();
    public bool ChainValid { get; init; }

    public bool IsExpired => DateTimeOffset.UtcNow > NotAfter;
    public bool IsNotYetValid => DateTimeOffset.UtcNow < NotBefore;
    public int DaysUntilExpiry => (int)(NotAfter - DateTimeOffset.UtcNow).TotalDays;
}
