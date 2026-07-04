using Rabits.Domain.Networking;

namespace Rabits.CLI.Rendering;

/// <summary>Shared Spectre markup helpers for presenting wireless data consistently.</summary>
internal static class NetworkFormatting
{
    /// <summary>A four-segment signal bar coloured by strength, followed by the dBm value.</summary>
    public static string Signal(SignalStrength rssi)
    {
        var bars = rssi.Bars;
        var colour = bars switch
        {
            >= 3 => "green",
            2 => "yellow",
            1 => "darkorange",
            _ => "red",
        };
        var filled = new string('█', bars);
        var empty = new string('─', 4 - bars);
        return $"[{colour}]{filled}[/][grey30]{empty}[/] [grey]{rssi.Dbm} dBm[/]";
    }

    public static string Encryption(EncryptionType encryption) => encryption switch
    {
        EncryptionType.Open => "[red]OPEN[/]",
        EncryptionType.Wep => "[red]WEP[/]",
        EncryptionType.Wpa => "[darkorange]WPA[/]",
        EncryptionType.Wpa2 => "[green]WPA2[/]",
        EncryptionType.Wpa3 => "[bold green]WPA3[/]",
        EncryptionType.WpaEnterprise => "[blue]WPA-ENT[/]",
        _ => "[grey]?[/]",
    };

    public static string Band(FrequencyBand band) => band switch
    {
        FrequencyBand.Band24GHz => "2.4 GHz",
        FrequencyBand.Band5GHz => "5 GHz",
        FrequencyBand.Band6GHz => "6 GHz",
        _ => "-",
    };
}
