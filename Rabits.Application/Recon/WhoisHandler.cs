using Rabits.Application.Abstractions;
using Rabits.Application.Security;
using Rabits.Domain.Auditing;
using Rabits.Domain.Operations;
using Rabits.Domain.Recon;

namespace Rabits.Application.Recon;

/// <summary>Use case: WHOIS lookup for a domain (passive).</summary>
public sealed class WhoisHandler
{
    public const string OperationName = "whois.lookup";

    private readonly IWhoisClient _whois;
    private readonly IAuthorizationGuard _guard;
    private readonly IAuditLog _audit;

    public WhoisHandler(IWhoisClient whois, IAuthorizationGuard guard, IAuditLog audit)
    {
        _whois = whois;
        _guard = guard;
        _audit = audit;
    }

    public async Task<WhoisResult> HandleAsync(string domain, CancellationToken cancellationToken = default)
    {
        var operation = RabitsOperation.Passive(OperationName, domain);
        await _guard.AuthorizeAsync(operation, cancellationToken);

        var result = await _whois.LookupAsync(domain, cancellationToken);
        await _audit.RecordAsync(operation, AuditOutcome.Completed,
            result.Registrar is { } r ? $"registrar: {r}" : "completed", cancellationToken);
        return result;
    }
}
