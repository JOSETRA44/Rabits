namespace Rabits.Domain.Networking;

/// <summary>
/// A Wi-Fi channel number together with the band it belongs to. The band can be inferred
/// from the channel number when only the number is known.
/// </summary>
public readonly record struct NetworkChannel(int Number, FrequencyBand Band)
{
    public static NetworkChannel FromNumber(int number) => new(number, InferBand(number));

    private static FrequencyBand InferBand(int channel) => channel switch
    {
        >= 1 and <= 14 => FrequencyBand.Band24GHz,
        >= 32 and <= 177 => FrequencyBand.Band5GHz,
        // 6 GHz channels (1–233) overlap 2.4/5 numbering, so callers that know the band
        // should pass it explicitly; this heuristic only covers the unambiguous ranges.
        _ => FrequencyBand.Unknown,
    };

    public override string ToString() => Band switch
    {
        FrequencyBand.Band24GHz => $"{Number} (2.4 GHz)",
        FrequencyBand.Band5GHz => $"{Number} (5 GHz)",
        FrequencyBand.Band6GHz => $"{Number} (6 GHz)",
        _ => Number.ToString(),
    };
}
