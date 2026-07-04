using Rabits.Application.Abstractions;
using Rabits.Application.Security;
using Rabits.Domain.Auditing;
using Rabits.Domain.Networking;
using Rabits.Domain.Operations;

namespace Rabits.Application.Wireless;

/// <summary>
/// Use case: enumerate nearby wireless networks. Passive by classification, but still routed
/// through the authorization gate and recorded in the audit trail, ordered strongest-first.
/// </summary>
public sealed class ScanWirelessNetworksHandler
{
    public const string OperationName = "wifi.scan";

    private readonly IWirelessScanner _scanner;
    private readonly IAuthorizationGuard _guard;
    private readonly IAuditLog _audit;

    public ScanWirelessNetworksHandler(IWirelessScanner scanner, IAuthorizationGuard guard, IAuditLog audit)
    {
        _scanner = scanner;
        _guard = guard;
        _audit = audit;
    }

    public async Task<IReadOnlyList<WirelessNetwork>> HandleAsync(CancellationToken cancellationToken = default)
    {
        var operation = RabitsOperation.Passive(OperationName);
        await _guard.AuthorizeAsync(operation, cancellationToken);

        try
        {
            var networks = await _scanner.ScanAsync(cancellationToken);
            var ordered = networks
                .OrderByDescending(n => n.Rssi.Dbm)
                .ToList();

            await _audit.RecordAsync(operation, AuditOutcome.Completed,
                $"{ordered.Count} network(s) observed", cancellationToken);

            return ordered;
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            await _audit.RecordAsync(operation, AuditOutcome.Failed, ex.Message, cancellationToken);
            throw;
        }
    }
}
