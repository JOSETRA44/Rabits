using System.Globalization;
using System.Windows.Data;
using System.Windows.Media;
using Rabits.Domain.Networking;

namespace Rabits.GUI.Converters;

/// <summary>Maps an <see cref="EncryptionType"/> to a status colour (open = danger, WPA3 = success).</summary>
public sealed class EncryptionToBrushConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object? parameter, CultureInfo culture)
    {
        var colour = value is EncryptionType e
            ? e switch
            {
                EncryptionType.Open => "#F85149",
                EncryptionType.Wep => "#F85149",
                EncryptionType.Wpa => "#D29922",
                EncryptionType.Wpa2 => "#3FB950",
                EncryptionType.Wpa3 => "#2EA043",
                EncryptionType.WpaEnterprise => "#2F81F7",
                _ => "#8B949E",
            }
            : "#8B949E";

        return new SolidColorBrush((Color)ColorConverter.ConvertFromString(colour));
    }

    public object ConvertBack(object value, Type targetType, object? parameter, CultureInfo culture)
        => Binding.DoNothing;
}

/// <summary>Colours a 0–100 signal quality: green (strong) → orange → red (weak).</summary>
public sealed class QualityToBrushConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object? parameter, CultureInfo culture)
    {
        var quality = value is int q ? q : 0;
        var colour = quality switch
        {
            >= 66 => "#3FB950",
            >= 40 => "#D29922",
            _ => "#F85149",
        };
        return new SolidColorBrush((Color)ColorConverter.ConvertFromString(colour));
    }

    public object ConvertBack(object value, Type targetType, object? parameter, CultureInfo culture)
        => Binding.DoNothing;
}

/// <summary>Maps a host's up/down boolean to a status colour.</summary>
public sealed class StatusToBrushConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object? parameter, CultureInfo culture)
        => new SolidColorBrush((Color)ColorConverter.ConvertFromString(value is true ? "#3FB950" : "#8B949E"));

    public object ConvertBack(object value, Type targetType, object? parameter, CultureInfo culture)
        => Binding.DoNothing;
}

/// <summary>Human-readable band label for a <see cref="FrequencyBand"/>.</summary>
public sealed class BandToTextConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object? parameter, CultureInfo culture) => value switch
    {
        FrequencyBand.Band24GHz => "2.4 GHz",
        FrequencyBand.Band5GHz => "5 GHz",
        FrequencyBand.Band6GHz => "6 GHz",
        _ => "—",
    };

    public object ConvertBack(object value, Type targetType, object? parameter, CultureInfo culture)
        => Binding.DoNothing;
}
