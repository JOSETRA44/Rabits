using Rabits.Domain.Networking;

namespace Rabits.Application.Abstractions;

/// <summary>
/// Port for enumerating nearby wireless networks. Implementations are passive: they read what
/// the adapter already hears and never transmit toward an access point.
/// </summary>
public interface IWirelessScanner
{
    /// <summary>True when this implementation can talk to a real adapter on the current host.</summary>
    bool IsSupported { get; }

    Task<IReadOnlyList<WirelessNetwork>> ScanAsync(CancellationToken cancellationToken = default);
}
