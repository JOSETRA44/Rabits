using Rabits.Domain.Recon;

namespace Rabits.Application.Abstractions;

/// <summary>Performs a WHOIS lookup over TCP/43. Passive — queries registry infrastructure.</summary>
public interface IWhoisClient
{
    Task<WhoisResult> LookupAsync(string domain, CancellationToken cancellationToken = default);
}
