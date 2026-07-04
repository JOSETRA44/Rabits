using Rabits.Domain.Networking;

namespace Rabits.GUI.ViewModels;

/// <summary>Presentation wrapper over a <see cref="DiscoveredHost"/> with sortable, display-ready fields.</summary>
public sealed class HostRowViewModel
{
    private readonly DiscoveredHost _host;

    public HostRowViewModel(DiscoveredHost host) => _host = host;

    public string Ip => _host.Address.ToString();
    public uint IpSortKey => _host.AddressSortKey;
    public bool IsUp => _host.IsUp;
    public string StatusText => _host.IsUp ? "up" : "down";
    public string Method => _host.Method.ToString();
    public string Mac => _host.Mac?.ToString() ?? "—";
    public string Vendor => _host.Vendor ?? "unknown";
    public string Hostname => _host.Hostname ?? "—";
    public double LatencyMs => _host.Latency?.TotalMilliseconds ?? double.MaxValue;
    public string LatencyText => _host.Latency is { } l ? $"{l.TotalMilliseconds:0} ms" : "—";
    public int OpenPortsCount => _host.OpenPorts.Count;
    public string OpenPortsText => _host.OpenPorts.Count > 0
        ? string.Join(", ", _host.OpenPorts.Select(p => p.ToString()))
        : "—";
}
