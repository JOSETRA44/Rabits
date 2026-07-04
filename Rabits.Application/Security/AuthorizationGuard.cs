using Microsoft.Extensions.Logging;
using Rabits.Application.Abstractions;
using Rabits.Domain.Auditing;
using Rabits.Domain.Engagement;
using Rabits.Domain.Operations;

namespace Rabits.Application.Security;

/// <summary>
/// Default hard-gate implementation. With no engagement scope loaded, only passive operations
/// are allowed; everything else is denied and audited. This is the class the plan calls the
/// "gate duro por scope file".
/// </summary>
public sealed class AuthorizationGuard : IAuthorizationGuard
{
    private readonly IScopePolicy _scope;
    private readonly IClock _clock;
    private readonly IAuditLog _audit;
    private readonly ILogger<AuthorizationGuard> _logger;

    public AuthorizationGuard(IScopePolicy scope, IClock clock, IAuditLog audit, ILogger<AuthorizationGuard> logger)
    {
        _scope = scope;
        _clock = clock;
        _audit = audit;
        _logger = logger;
    }

    public async Task AuthorizeAsync(RabitsOperation operation, CancellationToken cancellationToken = default)
    {
        var result = Evaluate(operation);

        if (!result.IsAuthorized)
        {
            await _audit.RecordAsync(operation, AuditOutcome.Denied, result.Reason, cancellationToken);
            _logger.LogWarning("Denied {Operation} against {Target}: {Reason}",
                operation.Name, operation.Target, result.Reason);
            throw new OutOfScopeException(operation, result.Reason);
        }

        // Passive operations are recorded by the use case itself; only audit the gate decision
        // for operations that actually touch a target.
        if (operation.Classification != OperationClassification.Passive)
            await _audit.RecordAsync(operation, AuditOutcome.Authorized, result.Reason, cancellationToken);
    }

    private AuthorizationResult Evaluate(RabitsOperation operation)
    {
        if (operation.Classification == OperationClassification.Passive)
            return AuthorizationResult.Allow("passive operation");

        var scope = _scope.Current;
        if (scope is null)
            return AuthorizationResult.Deny("no engagement scope loaded; active operations are disabled");

        return scope.Evaluate(operation, _clock.Now);
    }
}
