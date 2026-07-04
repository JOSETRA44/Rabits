using Rabits.Application.Abstractions;
using Rabits.Application.Security;
using Rabits.Domain.Auditing;
using Rabits.Domain.Operations;
using Rabits.Domain.Recon;

namespace Rabits.Application.Recon;

/// <summary>Use case: gather DNS records for a domain (passive). Audited but not scope-gated.</summary>
public sealed class DnsReconHandler
{
    public const string OperationName = "dns.lookup";

    private static readonly DnsRecordType[] DefaultTypes =
    {
        DnsRecordType.A, DnsRecordType.AAAA, DnsRecordType.CNAME,
        DnsRecordType.MX, DnsRecordType.NS, DnsRecordType.TXT, DnsRecordType.SOA,
    };

    private readonly IDnsResolver _dns;
    private readonly IAuthorizationGuard _guard;
    private readonly IAuditLog _audit;

    public DnsReconHandler(IDnsResolver dns, IAuthorizationGuard guard, IAuditLog audit)
    {
        _dns = dns;
        _guard = guard;
        _audit = audit;
    }

    public async Task<IReadOnlyList<DnsRecord>> HandleAsync(
        string domain, IReadOnlyList<DnsRecordType>? types = null, CancellationToken cancellationToken = default)
    {
        var operation = RabitsOperation.Passive(OperationName, domain);
        await _guard.AuthorizeAsync(operation, cancellationToken);

        var query = types is { Count: > 0 } ? types : DefaultTypes;
        var tasks = query.Select(t => _dns.QueryAsync(domain, t, cancellationToken));
        var records = (await Task.WhenAll(tasks)).SelectMany(r => r).ToList();

        await _audit.RecordAsync(operation, AuditOutcome.Completed, $"{records.Count} record(s)", cancellationToken);
        return records;
    }
}
