using System.Runtime.InteropServices;

namespace Rabits.Infrastructure.Interop;

/// <summary>
/// Minimal P/Invoke surface over Windows' Native Wifi (wlanapi.dll) needed for a passive scan:
/// open a handle, enumerate interfaces, and read the BSS list (BSSID, RSSI in dBm, frequency,
/// SSID and raw information elements). Layouts mirror the structures in wlanapi.h / wlantypes.h.
/// </summary>
internal static class WlanInterop
{
    private const string Wlanapi = "wlanapi.dll";

    [DllImport(Wlanapi)]
    internal static extern uint WlanOpenHandle(
        uint dwClientVersion, IntPtr pReserved, out uint pdwNegotiatedVersion, out IntPtr phClientHandle);

    [DllImport(Wlanapi)]
    internal static extern uint WlanCloseHandle(IntPtr hClientHandle, IntPtr pReserved);

    [DllImport(Wlanapi)]
    internal static extern void WlanFreeMemory(IntPtr pMemory);

    [DllImport(Wlanapi)]
    internal static extern uint WlanEnumInterfaces(
        IntPtr hClientHandle, IntPtr pReserved, out IntPtr ppInterfaceList);

    [DllImport(Wlanapi)]
    internal static extern uint WlanScan(
        IntPtr hClientHandle, [In] ref Guid pInterfaceGuid, IntPtr pDot11Ssid, IntPtr pIeData, IntPtr pReserved);

    [DllImport(Wlanapi)]
    internal static extern uint WlanGetNetworkBssList(
        IntPtr hClientHandle,
        [In] ref Guid pInterfaceGuid,
        IntPtr pDot11Ssid,
        Dot11BssType dot11BssType,
        [MarshalAs(UnmanagedType.Bool)] bool bSecurityEnabled,
        IntPtr pReserved,
        out IntPtr ppWlanBssList);

    internal const uint ClientVersion = 2;
    internal const uint Success = 0;

    internal enum Dot11BssType
    {
        Infrastructure = 1,
        Independent = 2,
        Any = 3,
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct WlanInterfaceInfoList
    {
        public uint dwNumberOfItems;
        public uint dwIndex;
        // WLAN_INTERFACE_INFO wlanInterfaceInfo[1] follows immediately.
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    internal struct WlanInterfaceInfo
    {
        public Guid InterfaceGuid;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)]
        public string strInterfaceDescription;
        public uint isState;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct Dot11Ssid
    {
        public uint uSSIDLength;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 32)]
        public byte[] ucSSID;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct WlanRateSet
    {
        public uint uRateSetLength;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 126)]
        public ushort[] usRateSet;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct WlanBssListHeader
    {
        public uint dwTotalSize;
        public uint dwNumberOfItems;
        // WLAN_BSS_ENTRY wlanBssEntries[1] follows immediately.
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct WlanBssEntry
    {
        public Dot11Ssid dot11Ssid;
        public uint uPhyId;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 6)]
        public byte[] dot11Bssid;
        public uint dot11BssType;
        public uint dot11BssPhyType;
        public int lRssi;
        public uint uLinkQuality;
        [MarshalAs(UnmanagedType.U1)]
        public bool bInRegDomain;
        public ushort usBeaconPeriod;
        public ulong ullTimestamp;
        public ulong ullHostTimestamp;
        public ushort usCapabilityInformation;
        public uint ulChCenterFrequency;
        public WlanRateSet wlanRateSet;
        public uint ulIeOffset;
        public uint ulIeSize;
    }
}
