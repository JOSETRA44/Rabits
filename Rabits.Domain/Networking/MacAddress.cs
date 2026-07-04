using System.Globalization;
using Rabits.Domain.Common;

namespace Rabits.Domain.Networking;

/// <summary>
/// A 48-bit IEEE 802 hardware address (a MAC / BSSID). Immutable value object with
/// value-based equality across its six octets.
/// </summary>
public readonly record struct MacAddress
{
    private readonly byte _b0, _b1, _b2, _b3, _b4, _b5;

    public MacAddress(ReadOnlySpan<byte> octets)
    {
        if (octets.Length != 6)
            throw new InvalidMacAddressException($"A MAC address needs exactly 6 octets, got {octets.Length}.");
        _b0 = octets[0]; _b1 = octets[1]; _b2 = octets[2];
        _b3 = octets[3]; _b4 = octets[4]; _b5 = octets[5];
    }

    /// <summary>The Organizationally Unique Identifier (first three octets), e.g. "AA:BB:CC".</summary>
    public string Oui => $"{_b0:X2}:{_b1:X2}:{_b2:X2}";

    /// <summary>True for the broadcast address FF:FF:FF:FF:FF:FF.</summary>
    public bool IsBroadcast => _b0 == 0xFF && _b1 == 0xFF && _b2 == 0xFF && _b3 == 0xFF && _b4 == 0xFF && _b5 == 0xFF;

    /// <summary>True when the locally-administered bit (bit 1 of the first octet) is set.</summary>
    public bool IsLocallyAdministered => (_b0 & 0x02) != 0;

    public byte[] ToBytes() => new[] { _b0, _b1, _b2, _b3, _b4, _b5 };

    public static MacAddress Parse(string value)
        => TryParse(value, out var mac)
            ? mac
            : throw new InvalidMacAddressException($"'{value}' is not a valid MAC address.");

    /// <summary>Accepts colon- or hyphen-separated hex ("AA:BB:CC:DD:EE:FF", "aa-bb-cc-dd-ee-ff").</summary>
    public static bool TryParse(string? value, out MacAddress mac)
    {
        mac = default;
        if (string.IsNullOrWhiteSpace(value)) return false;

        var parts = value.Split(new[] { ':', '-' }, StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length != 6) return false;

        var bytes = new byte[6];
        for (var i = 0; i < 6; i++)
        {
            if (parts[i].Length != 2 ||
                !byte.TryParse(parts[i], NumberStyles.HexNumber, CultureInfo.InvariantCulture, out bytes[i]))
                return false;
        }

        mac = new MacAddress(bytes);
        return true;
    }

    public override string ToString() => $"{_b0:X2}:{_b1:X2}:{_b2:X2}:{_b3:X2}:{_b4:X2}:{_b5:X2}";
}

public sealed class InvalidMacAddressException : DomainException
{
    public InvalidMacAddressException(string message) : base(message) { }
}
