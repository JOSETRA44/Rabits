using Rabits.Domain.Networking;
using Rabits.Infrastructure.Interop;

namespace Rabits.Tests.Infrastructure;

public class Ieee80211Tests
{
    [Theory]
    [InlineData(2412000, 1, FrequencyBand.Band24GHz)]
    [InlineData(2437000, 6, FrequencyBand.Band24GHz)]
    [InlineData(2484000, 14, FrequencyBand.Band24GHz)]
    [InlineData(5180000, 36, FrequencyBand.Band5GHz)]
    [InlineData(5955000, 1, FrequencyBand.Band6GHz)]
    public void Maps_frequency_to_channel_and_band(uint khz, int channel, FrequencyBand band)
    {
        var result = Ieee80211.ChannelFromFrequencyKhz(khz);
        Assert.Equal(channel, result.Number);
        Assert.Equal(band, result.Band);
    }

    [Fact]
    public void No_security_ie_without_privacy_bit_is_open()
        => Assert.Equal(EncryptionType.Open, Ieee80211.DetermineEncryption(Array.Empty<byte>(), 0x0000));

    [Fact]
    public void Privacy_bit_without_rsn_or_wpa_is_wep()
        => Assert.Equal(EncryptionType.Wep, Ieee80211.DetermineEncryption(Array.Empty<byte>(), 0x0010));

    [Fact]
    public void Rsn_with_sae_akm_is_wpa3()
    {
        var ie = Rsn(akmType: 0x08); // SAE
        Assert.Equal(EncryptionType.Wpa3, Ieee80211.DetermineEncryption(ie, 0x0010));
    }

    [Fact]
    public void Rsn_with_psk_akm_is_wpa2()
    {
        var ie = Rsn(akmType: 0x02); // PSK
        Assert.Equal(EncryptionType.Wpa2, Ieee80211.DetermineEncryption(ie, 0x0010));
    }

    [Fact]
    public void Rsn_with_dot1x_akm_is_enterprise()
    {
        var ie = Rsn(akmType: 0x01); // 802.1X
        Assert.Equal(EncryptionType.WpaEnterprise, Ieee80211.DetermineEncryption(ie, 0x0010));
    }

    /// <summary>Builds a minimal RSN information element with a single AKM suite of the given type.</summary>
    private static byte[] Rsn(byte akmType) => new byte[]
    {
        0x30, 0x12,                   // element id (48) + length (18)
        0x01, 0x00,                   // version
        0x00, 0x0F, 0xAC, 0x04,       // group cipher (CCMP)
        0x01, 0x00, 0x00, 0x0F, 0xAC, 0x04, // 1 pairwise cipher (CCMP)
        0x01, 0x00, 0x00, 0x0F, 0xAC, akmType, // 1 AKM suite
    };
}
