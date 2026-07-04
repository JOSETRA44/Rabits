using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Text;
using Microsoft.Extensions.Logging;
using Rabits.Application.Abstractions;
using Rabits.Domain.Networking;
using Rabits.Infrastructure.Interop;

namespace Rabits.Infrastructure.Wireless;

/// <summary>
/// <see cref="IWirelessScanner"/> backed by Windows Native Wifi (wlanapi.dll). It reads the BSS
/// list from every wireless interface — passive observation only, no frames are sent to any AP.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class NativeWlanScanner : IWirelessScanner
{
    private readonly ILogger<NativeWlanScanner> _logger;
    private readonly bool _triggerScan;
    private readonly TimeSpan _scanSettleDelay;

    public NativeWlanScanner(ILogger<NativeWlanScanner> logger, bool triggerScan = true, TimeSpan? scanSettleDelay = null)
    {
        _logger = logger;
        _triggerScan = triggerScan;
        _scanSettleDelay = scanSettleDelay ?? TimeSpan.FromSeconds(3);
    }

    public bool IsSupported => OperatingSystem.IsWindows();

    public async Task<IReadOnlyList<WirelessNetwork>> ScanAsync(CancellationToken cancellationToken = default)
    {
        if (!IsSupported)
            throw new PlatformNotSupportedException("The native WLAN scanner requires Windows.");

        var interfaces = OpenAndEnumerate(out var handle);
        try
        {
            if (interfaces.Count == 0)
            {
                _logger.LogWarning("No wireless interfaces found.");
                return Array.Empty<WirelessNetwork>();
            }

            if (_triggerScan)
            {
                foreach (var guid in interfaces)
                {
                    var g = guid;
                    WlanInterop.WlanScan(handle, ref g, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero);
                }
                await Task.Delay(_scanSettleDelay, cancellationToken);
            }

            var byBssid = new Dictionary<string, WirelessNetwork>(StringComparer.OrdinalIgnoreCase);
            foreach (var guid in interfaces)
            {
                cancellationToken.ThrowIfCancellationRequested();
                foreach (var network in ReadBssList(handle, guid))
                {
                    var key = network.Bssid.ToString();
                    // Keep the strongest observation of each BSSID across interfaces.
                    if (!byBssid.TryGetValue(key, out var existing) || network.Rssi.Dbm > existing.Rssi.Dbm)
                        byBssid[key] = network;
                }
            }

            return byBssid.Values.ToList();
        }
        finally
        {
            WlanInterop.WlanCloseHandle(handle, IntPtr.Zero);
        }
    }

    private List<Guid> OpenAndEnumerate(out IntPtr handle)
    {
        var result = WlanInterop.WlanOpenHandle(WlanInterop.ClientVersion, IntPtr.Zero, out _, out handle);
        if (result != WlanInterop.Success)
            throw new InvalidOperationException($"WlanOpenHandle failed (error {result}).");

        var enumResult = WlanInterop.WlanEnumInterfaces(handle, IntPtr.Zero, out var listPtr);
        if (enumResult != WlanInterop.Success)
        {
            WlanInterop.WlanCloseHandle(handle, IntPtr.Zero);
            throw new InvalidOperationException($"WlanEnumInterfaces failed (error {enumResult}).");
        }

        try
        {
            var header = Marshal.PtrToStructure<WlanInterop.WlanInterfaceInfoList>(listPtr);
            var infoSize = Marshal.SizeOf<WlanInterop.WlanInterfaceInfo>();
            var basePtr = IntPtr.Add(listPtr, 8); // past dwNumberOfItems + dwIndex

            var guids = new List<Guid>((int)header.dwNumberOfItems);
            for (var i = 0; i < header.dwNumberOfItems; i++)
            {
                var info = Marshal.PtrToStructure<WlanInterop.WlanInterfaceInfo>(IntPtr.Add(basePtr, i * infoSize));
                guids.Add(info.InterfaceGuid);
            }
            return guids;
        }
        finally
        {
            WlanInterop.WlanFreeMemory(listPtr);
        }
    }

    private IEnumerable<WirelessNetwork> ReadBssList(IntPtr handle, Guid interfaceGuid)
    {
        var guid = interfaceGuid;
        var result = WlanInterop.WlanGetNetworkBssList(
            handle, ref guid, IntPtr.Zero, WlanInterop.Dot11BssType.Any, false, IntPtr.Zero, out var listPtr);

        if (result != WlanInterop.Success || listPtr == IntPtr.Zero)
        {
            _logger.LogDebug("WlanGetNetworkBssList returned {Error} for interface {Guid}.", result, interfaceGuid);
            yield break;
        }

        var networks = new List<WirelessNetwork>();
        try
        {
            var header = Marshal.PtrToStructure<WlanInterop.WlanBssListHeader>(listPtr);
            var entrySize = Marshal.SizeOf<WlanInterop.WlanBssEntry>();
            var basePtr = IntPtr.Add(listPtr, 8); // past dwTotalSize + dwNumberOfItems

            for (var i = 0; i < header.dwNumberOfItems; i++)
            {
                var entryPtr = IntPtr.Add(basePtr, i * entrySize);
                var entry = Marshal.PtrToStructure<WlanInterop.WlanBssEntry>(entryPtr);
                networks.Add(MapEntry(entry, entryPtr));
            }
        }
        finally
        {
            WlanInterop.WlanFreeMemory(listPtr);
        }

        foreach (var n in networks)
            yield return n;
    }

    private static WirelessNetwork MapEntry(WlanInterop.WlanBssEntry entry, IntPtr entryPtr)
    {
        var ssidLength = (int)Math.Min(entry.dot11Ssid.uSSIDLength, 32u);
        var ssid = ssidLength > 0
            ? Encoding.UTF8.GetString(entry.dot11Ssid.ucSSID, 0, ssidLength)
            : string.Empty;

        var ies = ReadOnlySpan<byte>.Empty;
        byte[]? ieBuffer = null;
        if (entry.ulIeSize > 0)
        {
            ieBuffer = new byte[entry.ulIeSize];
            Marshal.Copy(IntPtr.Add(entryPtr, (int)entry.ulIeOffset), ieBuffer, 0, ieBuffer.Length);
            ies = ieBuffer;
        }

        var rssi = entry.lRssi != 0
            ? SignalStrength.FromDbm(entry.lRssi)
            : SignalStrength.FromQualityPercent((int)entry.uLinkQuality);

        var encryption = Ieee80211.DetermineEncryption(ies, entry.usCapabilityInformation);

        return new WirelessNetwork
        {
            Ssid = ssid,
            Bssid = new MacAddress(entry.dot11Bssid),
            Rssi = rssi,
            Channel = Ieee80211.ChannelFromFrequencyKhz(entry.ulChCenterFrequency),
            Encryption = encryption,
            Capabilities = encryption == EncryptionType.Open ? "OPEN" : encryption.ToString().ToUpperInvariant(),
        };
    }
}
