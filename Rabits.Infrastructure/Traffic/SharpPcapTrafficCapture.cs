using System.Threading.Channels;
using Microsoft.Extensions.Logging;
using PacketDotNet;
using Rabits.Application.Abstractions;
using Rabits.Application.Traffic;
using Rabits.Domain.Traffic;
using SharpPcap;
using SharpPcap.LibPcap;

namespace Rabits.Infrastructure.Traffic;

/// <summary>
/// Real packet capture via SharpPcap/Npcap. The capture callback fires on SharpPcap's own thread and
/// only does a non-blocking <c>TryWrite</c> into a bounded channel (DropOldest), so a burst of
/// traffic can never block capture or grow memory unbounded; a single consumer reads the stream.
/// </summary>
public sealed class SharpPcapTrafficCapture : ITrafficCapture
{
    private readonly ILogger<SharpPcapTrafficCapture> _logger;

    public SharpPcapTrafficCapture(ILogger<SharpPcapTrafficCapture> logger) => _logger = logger;

    public bool IsSupported => IsAvailable();

    /// <summary>Probes whether a libpcap/Npcap backend is present without throwing.</summary>
    public static bool IsAvailable()
    {
        try
        {
            _ = CaptureDeviceList.Instance;
            return true;
        }
        catch
        {
            return false;
        }
    }

    public IReadOnlyList<CaptureDevice> ListDevices()
    {
        try
        {
            return CaptureDeviceList.Instance
                .Select(d => new CaptureDevice(d.Name, d.Name, d.Description ?? d.Name))
                .ToList();
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Could not enumerate capture devices.");
            return Array.Empty<CaptureDevice>();
        }
    }

    public async IAsyncEnumerable<CapturedPacket> CaptureAsync(
        CaptureRequest request,
        [System.Runtime.CompilerServices.EnumeratorCancellation] CancellationToken cancellationToken = default)
    {
        var device = ResolveDevice(request.DeviceId)
            ?? throw new InvalidOperationException("No capture device available.");

        var channel = Channel.CreateBounded<CapturedPacket>(new BoundedChannelOptions(8192)
        {
            FullMode = BoundedChannelFullMode.DropOldest,
            SingleReader = true,
            SingleWriter = false,
        });

        void OnArrival(object sender, PacketCapture e)
        {
            var packet = Map(e.GetPacket());
            if (packet is not null) channel.Writer.TryWrite(packet); // never blocks the capture thread
        }

        device.OnPacketArrival += OnArrival;
        device.Open(new DeviceConfiguration
        {
            Mode = request.Promiscuous ? DeviceModes.Promiscuous : DeviceModes.None,
            ReadTimeout = 1000,
            Snaplen = request.SnapLength,
        });
        if (!string.IsNullOrWhiteSpace(request.BpfFilter))
            device.Filter = request.BpfFilter;

        device.StartCapture();
        _logger.LogInformation("Capturing on {Device}.", device.Description ?? device.Name);

        using var registration = cancellationToken.Register(() => channel.Writer.TryComplete());
        try
        {
            await foreach (var packet in channel.Reader.ReadAllAsync(CancellationToken.None))
                yield return packet;
        }
        finally
        {
            device.OnPacketArrival -= OnArrival;
            try { device.StopCapture(); } catch { /* already stopped */ }
            try { device.Close(); } catch { /* ignore */ }
        }
    }

    private static ILiveDevice? ResolveDevice(string? deviceId)
    {
        var devices = CaptureDeviceList.Instance;
        if (devices.Count == 0) return null;
        if (string.IsNullOrWhiteSpace(deviceId)) return devices[0];
        return devices.FirstOrDefault(d => d.Name == deviceId) ?? devices[0];
    }

    private static CapturedPacket? Map(RawCapture raw)
    {
        Packet parsed;
        try
        {
            parsed = Packet.ParsePacket(raw.LinkLayerType, raw.Data);
        }
        catch
        {
            return null;
        }

        var arp = parsed.Extract<ArpPacket>();
        if (arp is not null)
        {
            return Build(raw, TrafficProtocol.Arp,
                arp.SenderProtocolAddress.ToString(), arp.TargetProtocolAddress.ToString(),
                null, null, $"Who has {arp.TargetProtocolAddress}? Tell {arp.SenderProtocolAddress}");
        }

        var ip = parsed.Extract<IPPacket>();
        if (ip is null)
        {
            var eth = parsed.Extract<EthernetPacket>();
            return Build(raw, TrafficProtocol.Other,
                eth?.SourceHardwareAddress?.ToString() ?? "?",
                eth?.DestinationHardwareAddress?.ToString() ?? "?", null, null, "Non-IP frame");
        }

        var src = ip.SourceAddress.ToString();
        var dst = ip.DestinationAddress.ToString();

        var tcp = parsed.Extract<TcpPacket>();
        if (tcp is not null)
            return Build(raw, TrafficProtocol.Tcp, src, dst, tcp.SourcePort, tcp.DestinationPort, TcpFlags(tcp));

        var udp = parsed.Extract<UdpPacket>();
        if (udp is not null)
        {
            var proto = udp.SourcePort == 53 || udp.DestinationPort == 53 ? TrafficProtocol.Dns : TrafficProtocol.Udp;
            return Build(raw, proto, src, dst, udp.SourcePort, udp.DestinationPort,
                proto == TrafficProtocol.Dns ? "DNS" : "UDP datagram");
        }

        if (parsed.Extract<IcmpV4Packet>() is not null)
            return Build(raw, TrafficProtocol.Icmp, src, dst, null, null, "ICMP");
        if (parsed.Extract<IcmpV6Packet>() is not null)
            return Build(raw, TrafficProtocol.IcmpV6, src, dst, null, null, "ICMPv6");

        return Build(raw, TrafficProtocol.Other, src, dst, null, null, "IP packet");
    }

    private static string TcpFlags(TcpPacket tcp)
    {
        var flags = new List<string>(4);
        if (tcp.Synchronize) flags.Add("SYN");
        if (tcp.Acknowledgment) flags.Add("ACK");
        if (tcp.Finished) flags.Add("FIN");
        if (tcp.Reset) flags.Add("RST");
        if (tcp.Push) flags.Add("PSH");
        return flags.Count > 0 ? $"[{string.Join(",", flags)}]" : "TCP";
    }

    private static CapturedPacket Build(
        RawCapture raw, TrafficProtocol protocol, string src, string dst, int? sport, int? dport, string info)
        => new()
        {
            Timestamp = raw.Timeval.Date,
            Length = raw.Data.Length,
            Protocol = protocol,
            Source = src,
            Destination = dst,
            SourcePort = sport,
            DestinationPort = dport,
            Info = info,
        };
}
