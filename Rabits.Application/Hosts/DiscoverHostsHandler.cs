using System.Net;
using Rabits.Application.Abstractions;
using Rabits.Application.Security;
using Rabits.Domain.Auditing;
using Rabits.Domain.Networking;
using Rabits.Domain.Operations;

namespace Rabits.Application.Hosts;

/// <summary>
/// Use case: discover live hosts across a target range. This is an <b>active</b> operation — it
/// sends traffic to targets — so the whole range must be authorized by the engagement scope before
/// a single packet goes out. Liveness comes from ICMP and/or ARP; MAC → vendor, reverse DNS and a
/// TCP port scan enrich each host that answers.
/// </summary>
public sealed class DiscoverHostsHandler
{
    public const string OperationName = "host.discover";

    private readonly IHostProbe _probe;
    private readonly IArpResolver _arp;
    private readonly IOuiVendorLookup _oui;
    private readonly IPortScanner _portScanner;
    private readonly IReverseDnsResolver _reverseDns;
    private readonly IAuthorizationGuard _guard;
    private readonly IAuditLog _audit;

    public DiscoverHostsHandler(
        IHostProbe probe, IArpResolver arp, IOuiVendorLookup oui, IPortScanner portScanner,
        IReverseDnsResolver reverseDns, IAuthorizationGuard guard, IAuditLog audit)
    {
        _probe = probe;
        _arp = arp;
        _oui = oui;
        _portScanner = portScanner;
        _reverseDns = reverseDns;
        _guard = guard;
        _audit = audit;
    }

    public async Task<IReadOnlyList<DiscoveredHost>> HandleAsync(
        HostDiscoveryRequest request,
        IProgress<DiscoveredHost>? progress = null,
        CancellationToken cancellationToken = default)
    {
        if (!Subnet.TryParse(request.Target, out var subnet) || subnet is null)
            throw new ArgumentException($"'{request.Target}' is not a valid IP or CIDR.", nameof(request));

        // Active operation: the entire target range must be covered by the scope, or this throws.
        var operation = RabitsOperation.Active(OperationName, subnet.ToString());
        await _guard.AuthorizeAsync(operation, cancellationToken);

        try
        {
            var addresses = subnet.EnumerateHosts(request.MaxHosts).ToList();
            var ports = PortCatalog.For(request.Ports);
            using var throttle = new SemaphoreSlim(Math.Max(1, request.Concurrency));

            var tasks = addresses.Select(async address =>
            {
                await throttle.WaitAsync(cancellationToken);
                try
                {
                    return await InspectAsync(request, ports, address, progress, cancellationToken);
                }
                finally
                {
                    throttle.Release();
                }
            });

            var hosts = (await Task.WhenAll(tasks))
                .Where(h => h is not null)
                .Select(h => h!)
                .OrderBy(h => h.AddressSortKey)
                .ToList();

            await _audit.RecordAsync(operation, AuditOutcome.Completed,
                $"{hosts.Count} host(s) up of {addresses.Count} scanned in {subnet}", cancellationToken);

            return hosts;
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            await _audit.RecordAsync(operation, AuditOutcome.Failed, ex.Message, cancellationToken);
            throw;
        }
    }

    private async Task<DiscoveredHost?> InspectAsync(
        HostDiscoveryRequest request, IReadOnlyList<int> ports, IPAddress address,
        IProgress<DiscoveredHost>? progress, CancellationToken cancellationToken)
    {
        var probe = await _probe.ProbeAsync(address, cancellationToken);

        MacAddress? mac = null;
        var status = probe.Status;
        var method = probe.Method;

        if (request.ResolveMac)
        {
            mac = await _arp.ResolveAsync(address, cancellationToken);
            // A host that answers ARP is alive on-link even if it ignores ICMP.
            if (mac is not null && status != HostStatus.Up)
            {
                status = HostStatus.Up;
                method = DiscoveryMethod.ArpProbe;
            }
        }

        if (status != HostStatus.Up)
            return null;

        var vendor = mac is not null ? _oui.Lookup(mac.Value) : null;
        var hostname = request.ResolveHostname ? await _reverseDns.ResolveAsync(address, cancellationToken) : null;

        var openPorts = ports.Count > 0
            ? await _portScanner.ScanAsync(address, ports, cancellationToken)
            : Array.Empty<DiscoveredPort>();

        var host = new DiscoveredHost
        {
            Address = address,
            Status = status,
            Method = method,
            Mac = mac,
            Vendor = vendor,
            Hostname = hostname,
            Latency = probe.Latency,
            OpenPorts = openPorts,
        };

        progress?.Report(host);
        return host;
    }
}
