using Rabits.Domain.Networking;

namespace Rabits.Infrastructure.Interop;

/// <summary>
/// Helpers to interpret raw 802.11 beacon/probe data: classify the advertised encryption from the
/// information elements + capability bits, and map a center frequency to a channel and band.
/// </summary>
internal static class Ieee80211
{
    private const int ElementIdRsn = 48;      // 0x30
    private const int ElementIdVendor = 221;  // 0xDD
    private const ushort CapabilityPrivacy = 0x0010;

    // AKM suite selector types (last octet of an 00-0F-AC:x selector).
    private const byte AkmDot1x = 1;   // enterprise
    private const byte AkmPsk = 2;     // WPA2 personal
    private const byte AkmFtDot1x = 3; // enterprise (fast transition)
    private const byte AkmFtPsk = 4;
    private const byte AkmDot1xSha256 = 5; // enterprise
    private const byte AkmSae = 8;     // WPA3 personal
    private const byte AkmFtSae = 9;   // WPA3

    public static EncryptionType DetermineEncryption(ReadOnlySpan<byte> informationElements, ushort capabilityInformation)
    {
        var hasRsn = false;
        var hasWpa1 = false;
        EncryptionType rsnClass = EncryptionType.Wpa2;

        var i = 0;
        while (i + 2 <= informationElements.Length)
        {
            int id = informationElements[i];
            int len = informationElements[i + 1];
            var dataStart = i + 2;
            if (dataStart + len > informationElements.Length) break;
            var data = informationElements.Slice(dataStart, len);

            if (id == ElementIdRsn)
            {
                hasRsn = true;
                rsnClass = ClassifyRsn(data);
            }
            else if (id == ElementIdVendor && len >= 4 &&
                     data[0] == 0x00 && data[1] == 0x50 && data[2] == 0xF2 && data[3] == 0x01)
            {
                hasWpa1 = true;
            }

            i = dataStart + len;
        }

        if (hasRsn) return rsnClass;
        if (hasWpa1) return EncryptionType.Wpa;
        return (capabilityInformation & CapabilityPrivacy) != 0 ? EncryptionType.Wep : EncryptionType.Open;
    }

    private static EncryptionType ClassifyRsn(ReadOnlySpan<byte> rsn)
    {
        // version(2) group-cipher(4) pairwiseCount(2) pairwise(n*4) akmCount(2) akm(m*4)
        var p = 2 + 4;
        if (p + 2 > rsn.Length) return EncryptionType.Wpa2;

        int pairwiseCount = rsn[p] | (rsn[p + 1] << 8);
        p += 2 + pairwiseCount * 4;
        if (p + 2 > rsn.Length) return EncryptionType.Wpa2;

        int akmCount = rsn[p] | (rsn[p + 1] << 8);
        p += 2;

        var sawEnterprise = false;
        var sawSae = false;
        var sawPsk = false;

        for (var k = 0; k < akmCount; k++)
        {
            var suite = p + k * 4;
            if (suite + 4 > rsn.Length) break;
            var type = rsn[suite + 3];
            switch (type)
            {
                case AkmSae:
                case AkmFtSae:
                    sawSae = true;
                    break;
                case AkmDot1x:
                case AkmFtDot1x:
                case AkmDot1xSha256:
                    sawEnterprise = true;
                    break;
                case AkmPsk:
                case AkmFtPsk:
                    sawPsk = true;
                    break;
            }
        }

        if (sawSae) return EncryptionType.Wpa3;
        if (sawEnterprise) return EncryptionType.WpaEnterprise;
        if (sawPsk) return EncryptionType.Wpa2;
        return EncryptionType.Wpa2;
    }

    public static NetworkChannel ChannelFromFrequencyKhz(uint frequencyKhz)
    {
        var mhz = (int)(frequencyKhz / 1000);

        if (mhz is >= 2401 and <= 2499)
        {
            var ch = mhz == 2484 ? 14 : (mhz - 2407) / 5;
            return new NetworkChannel(ch, FrequencyBand.Band24GHz);
        }
        if (mhz is >= 5925 and <= 7125)
        {
            return new NetworkChannel((mhz - 5950) / 5, FrequencyBand.Band6GHz);
        }
        if (mhz is >= 4900 and <= 5895)
        {
            return new NetworkChannel((mhz - 5000) / 5, FrequencyBand.Band5GHz);
        }
        return new NetworkChannel(0, FrequencyBand.Unknown);
    }
}
