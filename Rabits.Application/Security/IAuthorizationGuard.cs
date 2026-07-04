using Rabits.Domain.Operations;

namespace Rabits.Application.Security;

/// <summary>
/// The single choke point every use case calls before touching a target. Passive operations
/// pass through; active/intrusive ones are checked against the engagement scope and audited.
/// Throws <see cref="Rabits.Domain.Engagement.OutOfScopeException"/> when an operation is denied.
/// </summary>
public interface IAuthorizationGuard
{
    Task AuthorizeAsync(RabitsOperation operation, CancellationToken cancellationToken = default);
}
