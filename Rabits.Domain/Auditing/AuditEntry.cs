using System.Security.Cryptography;
using System.Text;
using Rabits.Domain.Operations;

namespace Rabits.Domain.Auditing;

public enum AuditOutcome
{
    Authorized,
    Denied,
    Completed,
    Failed,
}

/// <summary>
/// One tamper-evident record in the engagement audit trail. Each entry embeds the hash of the
/// previous entry, so any later modification or deletion breaks the chain and is detectable.
/// </summary>
public sealed record AuditEntry
{
    public required long Sequence { get; init; }
    public required DateTimeOffset Timestamp { get; init; }
    public required string Operator { get; init; }
    public required string OperationName { get; init; }
    public required OperationClassification Classification { get; init; }
    public required string Target { get; init; }
    public required AuditOutcome Outcome { get; init; }
    public string Detail { get; init; } = string.Empty;

    /// <summary>Hex-encoded SHA-256 of the preceding entry (all-zero genesis for the first).</summary>
    public required string PreviousHash { get; init; }

    /// <summary>Hex-encoded SHA-256 over this entry's content plus <see cref="PreviousHash"/>.</summary>
    public required string Hash { get; init; }

    public const string GenesisHash = "0000000000000000000000000000000000000000000000000000000000000000";

    public static AuditEntry Create(
        long sequence,
        DateTimeOffset timestamp,
        string @operator,
        RabitsOperation operation,
        AuditOutcome outcome,
        string detail,
        string previousHash)
    {
        var payload = string.Join('|',
            sequence,
            timestamp.ToUnixTimeMilliseconds(),
            @operator,
            operation.Name,
            operation.Classification,
            operation.Target,
            outcome,
            detail,
            previousHash);

        var hash = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(payload))).ToLowerInvariant();

        return new AuditEntry
        {
            Sequence = sequence,
            Timestamp = timestamp,
            Operator = @operator,
            OperationName = operation.Name,
            Classification = operation.Classification,
            Target = operation.Target,
            Outcome = outcome,
            Detail = detail,
            PreviousHash = previousHash,
            Hash = hash,
        };
    }
}
