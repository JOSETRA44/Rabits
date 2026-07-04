namespace Rabits.Domain.Auth;

/// <summary>Aggregate result of a credential audit run.</summary>
public sealed record CredentialAuditSummary
{
    public required int Attempted { get; init; }
    public required TimeSpan Elapsed { get; init; }
    public IReadOnlyList<Credential> Successes { get; init; } = Array.Empty<Credential>();
    public int Errors { get; init; }
    public bool StoppedEarly { get; init; }

    public int Failures => Attempted - Successes.Count - Errors;
    public bool AnySuccess => Successes.Count > 0;
}
