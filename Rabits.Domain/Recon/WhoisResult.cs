namespace Rabits.Domain.Recon;

/// <summary>Parsed and raw output of a WHOIS lookup.</summary>
public sealed record WhoisResult
{
    public required string Query { get; init; }
    public required string Server { get; init; }
    public required string Raw { get; init; }
    public string? Registrar { get; init; }
    public DateTimeOffset? CreatedOn { get; init; }
    public DateTimeOffset? ExpiresOn { get; init; }
    public IReadOnlyList<string> NameServers { get; init; } = Array.Empty<string>();

    public int? DaysUntilExpiry => ExpiresOn is { } e ? (int)(e - DateTimeOffset.UtcNow).TotalDays : null;
}
