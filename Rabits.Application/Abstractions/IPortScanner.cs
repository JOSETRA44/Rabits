using System.Net;
using Rabits.Domain.Networking;

namespace Rabits.Application.Abstractions;

/// <summary>Probes a set of TCP ports on a host and reports which are open.</summary>
public interface IPortScanner
{
    Task<IReadOnlyList<DiscoveredPort>> ScanAsync(
        IPAddress address, IReadOnlyList<int> ports, CancellationToken cancellationToken = default);
}
