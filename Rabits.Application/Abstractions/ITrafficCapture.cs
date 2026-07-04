using Rabits.Application.Traffic;
using Rabits.Domain.Traffic;

namespace Rabits.Application.Abstractions;

/// <summary>
/// Port for live packet capture. Passive — it only listens on an interface. Implementations stream
/// packets through a bounded buffer so a high packet rate cannot exhaust memory.
/// </summary>
public interface ITrafficCapture
{
    /// <summary>True when a real capture backend (e.g. Npcap) is available on this host.</summary>
    bool IsSupported { get; }

    IReadOnlyList<CaptureDevice> ListDevices();

    /// <summary>Streams captured packets until the token is cancelled.</summary>
    IAsyncEnumerable<CapturedPacket> CaptureAsync(CaptureRequest request, CancellationToken cancellationToken = default);
}
