using System.Net;
using Rabits.Application.Abstractions;

namespace Rabits.Infrastructure.Hosts;

/// <summary>Best-effort reverse DNS via <see cref="Dns"/>; returns null when no PTR record resolves.</summary>
public sealed class DnsReverseResolver : IReverseDnsResolver
{
    public async Task<string?> ResolveAsync(IPAddress address, CancellationToken cancellationToken = default)
    {
        try
        {
            var entry = await Dns.GetHostEntryAsync(address).WaitAsync(cancellationToken);
            return string.IsNullOrWhiteSpace(entry.HostName) ? null : entry.HostName;
        }
        catch (Exception)
        {
            return null;
        }
    }
}
