using System.Threading.Channels;
using Rabits.Application.Abstractions;
using Rabits.Application.Traffic;
using Rabits.Domain.Traffic;

namespace Rabits.Infrastructure.Traffic;

/// <summary>
/// Synthetic capture backend for demos, development and tests without Npcap. Generates a realistic
/// mix of packets through the same bounded-channel pipeline as the real capture, so the whole
/// streaming/backpressure path is exercised identically.
/// </summary>
public sealed class SimulatedTrafficCapture : ITrafficCapture
{
    private static readonly string[] LocalHosts = { "192.168.1.10", "192.168.1.22", "10.0.0.5", "192.168.1.1" };
    private static readonly string[] RemoteHosts = { "93.184.216.34", "142.250.80.14", "13.107.42.14", "1.1.1.1" };

    public bool IsSupported => true;

    public IReadOnlyList<CaptureDevice> ListDevices()
        => new[] { new CaptureDevice("simulated", "Simulated", "Rabits simulated interface (no Npcap)") };

    public async IAsyncEnumerable<CapturedPacket> CaptureAsync(
        CaptureRequest request,
        [System.Runtime.CompilerServices.EnumeratorCancellation] CancellationToken cancellationToken = default)
    {
        var channel = Channel.CreateBounded<CapturedPacket>(new BoundedChannelOptions(4096)
        {
            FullMode = BoundedChannelFullMode.DropOldest,
            SingleReader = true,
            SingleWriter = true,
        });

        _ = Task.Run(() => ProduceAsync(channel.Writer, cancellationToken), cancellationToken);

        await foreach (var packet in channel.Reader.ReadAllAsync(CancellationToken.None))
            yield return packet;
    }

    private static async Task ProduceAsync(ChannelWriter<CapturedPacket> writer, CancellationToken cancellationToken)
    {
        var random = new Random();
        try
        {
            while (!cancellationToken.IsCancellationRequested)
            {
                for (var i = 0; i < 8 && !cancellationToken.IsCancellationRequested; i++)
                    writer.TryWrite(NextPacket(random));

                await Task.Delay(15, cancellationToken);
            }
        }
        catch (OperationCanceledException)
        {
            // expected on stop
        }
        finally
        {
            writer.TryComplete();
        }
    }

    private static CapturedPacket NextPacket(Random random)
    {
        var roll = random.Next(100);
        var (protocol, dport) = roll switch
        {
            < 55 => (TrafficProtocol.Tcp, 443),
            < 70 => (TrafficProtocol.Tcp, 80),
            < 85 => (TrafficProtocol.Udp, random.Next(1024, 60000)),
            < 92 => (TrafficProtocol.Dns, 53),
            < 97 => (TrafficProtocol.Icmp, 0),
            _ => (TrafficProtocol.Arp, 0),
        };

        var local = LocalHosts[random.Next(LocalHosts.Length)];
        var remote = RemoteHosts[random.Next(RemoteHosts.Length)];
        var outbound = random.Next(2) == 0;
        var src = outbound ? local : remote;
        var dst = outbound ? remote : local;
        var length = random.Next(54, 1514);

        int? sport = protocol is TrafficProtocol.Tcp or TrafficProtocol.Udp or TrafficProtocol.Dns
            ? random.Next(1024, 60000) : null;
        int? destPort = protocol is TrafficProtocol.Tcp or TrafficProtocol.Udp or TrafficProtocol.Dns
            ? dport : null;

        return new CapturedPacket
        {
            Timestamp = DateTimeOffset.Now,
            Length = length,
            Protocol = protocol,
            Source = src,
            Destination = dst,
            SourcePort = sport,
            DestinationPort = destPort,
            Info = protocol switch
            {
                TrafficProtocol.Arp => $"Who has {dst}? Tell {src}",
                TrafficProtocol.Icmp => "Echo (ping) request",
                TrafficProtocol.Dns => "Standard query",
                _ => $"{protocol} segment, {length} bytes",
            },
        };
    }
}
