using Rabits.Application.Abstractions;
using Rabits.Application.Security;
using Rabits.Domain.Auditing;
using Rabits.Domain.Operations;
using Rabits.Domain.Recon;

namespace Rabits.Application.Recon;

/// <summary>
/// Use case: enumerate subdomains by resolving a wordlist of candidate labels against the domain
/// (passive DNS queries). Concurrency-bounded; reports each hit as it is found.
/// </summary>
public sealed class EnumerateSubdomainsHandler
{
    public const string OperationName = "subdomain.enum";

    private readonly IDnsResolver _dns;
    private readonly ISubdomainWordlist _wordlist;
    private readonly IAuthorizationGuard _guard;
    private readonly IAuditLog _audit;

    public EnumerateSubdomainsHandler(
        IDnsResolver dns, ISubdomainWordlist wordlist, IAuthorizationGuard guard, IAuditLog audit)
    {
        _dns = dns;
        _wordlist = wordlist;
        _guard = guard;
        _audit = audit;
    }

    public async Task<IReadOnlyList<Subdomain>> HandleAsync(
        string domain, int concurrency = 32, IProgress<Subdomain>? progress = null,
        CancellationToken cancellationToken = default)
    {
        var operation = RabitsOperation.Passive(OperationName, domain);
        await _guard.AuthorizeAsync(operation, cancellationToken);

        using var throttle = new SemaphoreSlim(Math.Max(1, concurrency));
        var root = domain.Trim().TrimEnd('.');

        var tasks = _wordlist.Labels.Select(async label =>
        {
            await throttle.WaitAsync(cancellationToken);
            try
            {
                var candidate = $"{label}.{root}";
                var addresses = new List<string>();
                foreach (var type in new[] { DnsRecordType.A, DnsRecordType.AAAA })
                    addresses.AddRange((await _dns.QueryAsync(candidate, type, cancellationToken)).Select(r => r.Value));

                if (addresses.Count == 0) return null;

                var hit = new Subdomain(candidate, addresses);
                progress?.Report(hit);
                return hit;
            }
            finally
            {
                throttle.Release();
            }
        });

        var found = (await Task.WhenAll(tasks))
            .Where(s => s is not null)
            .Select(s => s!)
            .OrderBy(s => s.Name, StringComparer.OrdinalIgnoreCase)
            .ToList();

        await _audit.RecordAsync(operation, AuditOutcome.Completed,
            $"{found.Count} of {_wordlist.Labels.Count} candidates resolved", cancellationToken);
        return found;
    }
}
