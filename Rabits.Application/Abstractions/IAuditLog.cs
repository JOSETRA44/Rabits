using Rabits.Domain.Auditing;
using Rabits.Domain.Operations;

namespace Rabits.Application.Abstractions;

/// <summary>
/// Append-only, tamper-evident engagement log. Implementations own sequencing and hash-chaining;
/// callers just describe what happened.
/// </summary>
public interface IAuditLog
{
    Task<AuditEntry> RecordAsync(
        RabitsOperation operation,
        AuditOutcome outcome,
        string detail,
        CancellationToken cancellationToken = default);

    Task<IReadOnlyList<AuditEntry>> ReadAllAsync(CancellationToken cancellationToken = default);

    /// <summary>Recomputes the chain and reports whether it is intact.</summary>
    Task<bool> VerifyAsync(CancellationToken cancellationToken = default);
}
