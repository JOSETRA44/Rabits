using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using Rabits.Application.Abstractions;
using Rabits.Domain.Networking;

namespace Rabits.Infrastructure.Hosts;

/// <summary>
/// Resolves a hardware address for an on-link IPv4 host via the Windows ARP helper
/// (<c>SendARP</c> in iphlpapi.dll). Returns null for off-link or non-responding hosts.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class SendArpResolver : IArpResolver
{
    [DllImport("iphlpapi.dll", ExactSpelling = true)]
    private static extern int SendARP(uint destIp, uint srcIp, byte[] macAddr, ref uint physAddrLen);

    public Task<MacAddress?> ResolveAsync(IPAddress address, CancellationToken cancellationToken = default)
    {
        if (address.AddressFamily != AddressFamily.InterNetwork)
            return Task.FromResult<MacAddress?>(null);

        // SendARP blocks; keep the sweep responsive by offloading it.
        return Task.Run(() =>
        {
            var destIp = BitConverter.ToUInt32(address.GetAddressBytes(), 0);
            var buffer = new byte[6];
            var length = (uint)buffer.Length;

            try
            {
                if (SendARP(destIp, 0, buffer, ref length) == 0 && length >= 6)
                    return (MacAddress?)new MacAddress(buffer);
            }
            catch (Exception)
            {
                // iphlpapi unavailable or transient failure — treat as unresolved.
            }

            return null;
        }, cancellationToken);
    }
}
