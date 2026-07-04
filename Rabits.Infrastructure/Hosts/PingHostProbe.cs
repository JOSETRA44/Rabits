using System.Net;
using System.Net.NetworkInformation;
using Rabits.Application.Abstractions;
using Rabits.Domain.Networking;

namespace Rabits.Infrastructure.Hosts;

/// <summary>ICMP-echo liveness probe (managed <see cref="Ping"/>; no elevation required on Windows).</summary>
public sealed class PingHostProbe : IHostProbe
{
    private readonly int _timeoutMs;

    public PingHostProbe(int timeoutMs = 800) => _timeoutMs = timeoutMs;

    public async Task<HostProbeResult> ProbeAsync(IPAddress address, CancellationToken cancellationToken = default)
    {
        using var ping = new Ping();
        try
        {
            var reply = await ping.SendPingAsync(address, _timeoutMs);
            return reply.Status == IPStatus.Success
                ? new HostProbeResult(HostStatus.Up, TimeSpan.FromMilliseconds(reply.RoundtripTime), DiscoveryMethod.IcmpEcho)
                : HostProbeResult.Down;
        }
        catch (PingException)
        {
            return HostProbeResult.Down;
        }
        catch (Exception) when (!cancellationToken.IsCancellationRequested)
        {
            return HostProbeResult.Down;
        }
    }
}
