using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using Microsoft.Extensions.Logging;
using Rabits.Application.Abstractions;
using Rabits.Domain.Recon;

namespace Rabits.Infrastructure.Recon;

/// <summary>
/// <see cref="IDnsResolver"/> that speaks DNS directly over UDP/53 using <see cref="DnsWire"/>.
/// Uses the OS-configured resolvers first, then public fallbacks.
/// </summary>
public sealed class DnsUdpClient : IDnsResolver
{
    private readonly IReadOnlyList<IPAddress> _servers;
    private readonly int _timeoutMs;
    private readonly ILogger<DnsUdpClient> _logger;

    public DnsUdpClient(ILogger<DnsUdpClient> logger, IEnumerable<IPAddress>? servers = null, int timeoutMs = 4000)
    {
        _logger = logger;
        _timeoutMs = timeoutMs;
        _servers = (servers?.ToList() is { Count: > 0 } provided ? provided : DiscoverServers());
    }

    public async Task<IReadOnlyList<DnsRecord>> QueryAsync(
        string name, DnsRecordType type, CancellationToken cancellationToken = default)
    {
        var id = (ushort)Random.Shared.Next(1, ushort.MaxValue);
        var query = DnsWire.BuildQuery(id, name, type);

        foreach (var server in _servers)
        {
            try
            {
                var response = await ExchangeAsync(server, query, cancellationToken);
                if (response is null) continue;

                var (rcode, records) = DnsWire.Parse(response, type);
                if (rcode is 0 or 3) // NoError or NXDomain are authoritative answers; stop querying
                    return records;
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                throw;
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "DNS query to {Server} for {Name}/{Type} failed.", server, name, type);
            }
        }

        return Array.Empty<DnsRecord>();
    }

    private async Task<byte[]?> ExchangeAsync(IPAddress server, byte[] query, CancellationToken cancellationToken)
    {
        using var udp = new UdpClient(server.AddressFamily);
        udp.Connect(server, 53);
        await udp.SendAsync(query, cancellationToken);

        using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeoutCts.CancelAfter(_timeoutMs);
        try
        {
            var result = await udp.ReceiveAsync(timeoutCts.Token);
            return result.Buffer;
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            return null; // timed out on this server
        }
    }

    private static List<IPAddress> DiscoverServers()
    {
        var servers = new List<IPAddress>();
        try
        {
            foreach (var nic in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (nic.OperationalStatus != OperationalStatus.Up) continue;
                foreach (var dns in nic.GetIPProperties().DnsAddresses)
                    if (dns.AddressFamily == AddressFamily.InterNetwork && !servers.Contains(dns))
                        servers.Add(dns);
            }
        }
        catch
        {
            // fall through to public resolvers
        }

        servers.Add(IPAddress.Parse("1.1.1.1"));
        servers.Add(IPAddress.Parse("8.8.8.8"));
        return servers;
    }
}
