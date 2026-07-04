using Rabits.Domain.Recon;

namespace Rabits.Application.Abstractions;

/// <summary>Queries DNS for resource records of a given type. Passive — hits resolvers, not the target.</summary>
public interface IDnsResolver
{
    Task<IReadOnlyList<DnsRecord>> QueryAsync(
        string name, DnsRecordType type, CancellationToken cancellationToken = default);
}
