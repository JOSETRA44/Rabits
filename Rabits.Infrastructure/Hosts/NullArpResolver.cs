using System.Net;
using Rabits.Application.Abstractions;
using Rabits.Domain.Networking;

namespace Rabits.Infrastructure.Hosts;

/// <summary>Fallback ARP resolver for non-Windows hosts; never resolves a hardware address.</summary>
public sealed class NullArpResolver : IArpResolver
{
    public Task<MacAddress?> ResolveAsync(IPAddress address, CancellationToken cancellationToken = default)
        => Task.FromResult<MacAddress?>(null);
}
