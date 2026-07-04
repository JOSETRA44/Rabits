namespace Rabits.Application.Auth;

/// <summary>Parameters for a credential audit run.</summary>
public sealed record CredentialAuditRequest
{
    public required AuthTarget Target { get; init; }
    public required IReadOnlyList<string> Usernames { get; init; }
    public required IReadOnlyList<string> Passwords { get; init; }

    /// <summary>Maximum simultaneous authentication attempts.</summary>
    public int Concurrency { get; init; } = 8;

    /// <summary>Stop the whole run as soon as one valid credential is found.</summary>
    public bool StopOnSuccess { get; init; } = true;

    /// <summary>Hard cap on the number of attempts (safety brake against runaway runs).</summary>
    public int MaxAttempts { get; init; } = 5000;
}
