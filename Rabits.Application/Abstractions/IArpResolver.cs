using System.Net;
using Rabits.Domain.Networking;

namespace Rabits.Application.Abstractions;

/// <summary>Resolves the hardware address of an on-link host (e.g. via an ARP request).</summary>
public interface IArpResolver
{
    Task<MacAddress?> ResolveAsync(IPAddress address, CancellationToken cancellationToken = default);
}
