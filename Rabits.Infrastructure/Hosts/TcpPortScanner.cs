using System.Net;
using System.Net.Sockets;
using Rabits.Application.Abstractions;
using Rabits.Application.Hosts;
using Rabits.Domain.Networking;

namespace Rabits.Infrastructure.Hosts;

/// <summary>
/// TCP connect scanner. Attempts a full connect to each port with a short timeout and bounded
/// concurrency, reporting the ports that accept. Only open ports are returned.
/// </summary>
public sealed class TcpPortScanner : IPortScanner
{
    private readonly int _timeoutMs;
    private readonly int _concurrency;

    public TcpPortScanner(int timeoutMs = 500, int concurrency = 200)
    {
        _timeoutMs = timeoutMs;
        _concurrency = concurrency;
    }

    public async Task<IReadOnlyList<DiscoveredPort>> ScanAsync(
        IPAddress address, IReadOnlyList<int> ports, CancellationToken cancellationToken = default)
    {
        using var throttle = new SemaphoreSlim(Math.Max(1, _concurrency));

        var tasks = ports.Select(async port =>
        {
            await throttle.WaitAsync(cancellationToken);
            try
            {
                return await ProbePortAsync(address, port, cancellationToken);
            }
            finally
            {
                throttle.Release();
            }
        });

        var results = await Task.WhenAll(tasks);
        return results.Where(p => p is not null).Select(p => p!).OrderBy(p => p.Number).ToList();
    }

    private async Task<DiscoveredPort?> ProbePortAsync(IPAddress address, int port, CancellationToken cancellationToken)
    {
        using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeoutCts.CancelAfter(_timeoutMs);

        using var socket = new Socket(address.AddressFamily, SocketType.Stream, ProtocolType.Tcp);
        try
        {
            await socket.ConnectAsync(address, port, timeoutCts.Token);
            return new DiscoveredPort(port, PortStatus.Open, PortCatalog.ServiceName(port));
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw; // caller cancelled the whole scan
        }
        catch (Exception)
        {
            // Timeout, connection refused, or unreachable — not open.
            return null;
        }
    }
}
