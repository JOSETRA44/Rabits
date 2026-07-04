using Rabits.Domain.Recon;

namespace Rabits.Domain.Layer7;

/// <summary>A candidate secret found in a downloaded resource. The raw value is never stored — only a
/// redacted preview — so findings can be displayed and logged safely.</summary>
public sealed record SecretFinding
{
    public required string RuleName { get; init; }
    public required string Category { get; init; }
    public required SecurityFindingSeverity Severity { get; init; }

    /// <summary>Masked preview of the match (first/last chars kept, middle redacted).</summary>
    public required string RedactedMatch { get; init; }

    /// <summary>Where it was found (resource URL or descriptor).</summary>
    public required string Source { get; init; }

    /// <summary>Optional Shannon entropy of the match (set for entropy-based findings).</summary>
    public double? Entropy { get; init; }

    /// <summary>De-duplication key: same rule + same value + same source is one finding.</summary>
    public string Key => $"{RuleName}|{RedactedMatch}|{Source}";
}
