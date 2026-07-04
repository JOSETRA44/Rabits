using Rabits.Application.Abstractions;
using Rabits.Domain.Networking;

namespace Rabits.Infrastructure.Wireless;

/// <summary>
/// Deterministic sample scanner for development and demos on hosts without a wireless adapter.
/// Selected automatically when the native scanner reports it is unsupported, or forced via options.
/// </summary>
public sealed class FakeWirelessScanner : IWirelessScanner
{
    public bool IsSupported => true;

    public Task<IReadOnlyList<WirelessNetwork>> ScanAsync(CancellationToken cancellationToken = default)
    {
        IReadOnlyList<WirelessNetwork> sample = new List<WirelessNetwork>
        {
            Net("CORP-SECURE", "3C:5A:B4:11:22:33", -41, 36, FrequencyBand.Band5GHz, EncryptionType.Wpa3),
            Net("CORP-GUEST", "3C:5A:B4:11:22:34", -47, 6, FrequencyBand.Band24GHz, EncryptionType.Wpa2),
            Net("Home-2.4", "A0:63:91:AB:CD:EF", -58, 11, FrequencyBand.Band24GHz, EncryptionType.Wpa2),
            Net("IoT-Hub", "F4:F5:D8:01:02:03", -66, 1, FrequencyBand.Band24GHz, EncryptionType.Wpa),
            Net("FreeCoffee", "00:1A:2B:3C:4D:5E", -71, 3, FrequencyBand.Band24GHz, EncryptionType.Open),
            Net("Neighbor-5G", "DC:A6:32:99:88:77", -79, 149, FrequencyBand.Band5GHz, EncryptionType.Wpa2),
            Net("", "B8:27:EB:AA:BB:CC", -83, 6, FrequencyBand.Band24GHz, EncryptionType.Wpa2),
            Net("Legacy-WEP", "00:0C:29:12:34:56", -88, 11, FrequencyBand.Band24GHz, EncryptionType.Wep),
        };

        return Task.FromResult(sample);
    }

    private static WirelessNetwork Net(string ssid, string bssid, int dbm, int channel, FrequencyBand band, EncryptionType enc)
        => new()
        {
            Ssid = ssid,
            Bssid = MacAddress.Parse(bssid),
            Rssi = SignalStrength.FromDbm(dbm),
            Channel = new NetworkChannel(channel, band),
            Encryption = enc,
            Capabilities = enc == EncryptionType.Open ? "OPEN" : enc.ToString().ToUpperInvariant(),
        };
}
