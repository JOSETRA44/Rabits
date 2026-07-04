using System.Runtime.CompilerServices;
using Rabits.Application.Abstractions;
using Rabits.Application.Security;
using Rabits.Domain.Auditing;
using Rabits.Domain.Operations;
using Rabits.Domain.Traffic;

namespace Rabits.Application.Traffic;

/// <summary>
/// Use case: capture live traffic on an interface. Passive by classification, routed through the
/// authorization gate and audited; the packet count is recorded when the stream ends (even on
/// cancellation). The stream itself is produced lazily so consumers control the pace.
/// </summary>
public sealed class CaptureTrafficHandler
{
    public const string OperationName = "traffic.capture";

    private readonly ITrafficCapture _capture;
    private readonly IAuthorizationGuard _guard;
    private readonly IAuditLog _audit;

    public CaptureTrafficHandler(ITrafficCapture capture, IAuthorizationGuard guard, IAuditLog audit)
    {
        _capture = capture;
        _guard = guard;
        _audit = audit;
    }

    public bool IsSupported => _capture.IsSupported;

    public IReadOnlyList<CaptureDevice> ListDevices() => _capture.ListDevices();

    public async IAsyncEnumerable<CapturedPacket> CaptureAsync(
        CaptureRequest request, [EnumeratorCancellation] CancellationToken cancellationToken = default)
    {
        var operation = RabitsOperation.Passive(OperationName, request.DeviceId ?? "default");
        await _guard.AuthorizeAsync(operation, cancellationToken);

        var count = 0L;
        try
        {
            await foreach (var packet in _capture.CaptureAsync(request, cancellationToken).WithCancellation(cancellationToken))
            {
                count++;
                yield return packet;
            }
        }
        finally
        {
            // Record the session outcome even when the consumer cancels the stream.
            await _audit.RecordAsync(operation, AuditOutcome.Completed, $"{count} packet(s) captured", CancellationToken.None);
        }
    }
}
