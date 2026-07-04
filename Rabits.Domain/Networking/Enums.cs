namespace Rabits.Domain.Networking;

/// <summary>Link-layer confidentiality/authentication scheme advertised by an access point.</summary>
public enum EncryptionType
{
    Unknown = 0,
    Open,
    Wep,
    Wpa,
    Wpa2,
    Wpa3,
    WpaEnterprise,
}

/// <summary>Radio frequency band a network operates on.</summary>
public enum FrequencyBand
{
    Unknown = 0,
    Band24GHz,
    Band5GHz,
    Band6GHz,
}
