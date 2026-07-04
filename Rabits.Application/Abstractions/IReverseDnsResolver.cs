using System.Net;

namespace Rabits.Application.Abstractions;

/// <summary>Best-effort reverse DNS (PTR) lookup for a host address.</summary>
public interface IReverseDnsResolver
{
    Task<string?> ResolveAsync(IPAddress address, CancellationToken cancellationToken = default);
}
