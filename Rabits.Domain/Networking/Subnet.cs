using System.Net;
using System.Net.Sockets;

namespace Rabits.Domain.Networking;

/// <summary>
/// An IP network in CIDR notation. Immutable; the stored network address is always masked to the
/// prefix. Supports address/subnet containment and (for IPv4) enumeration of usable host addresses.
/// </summary>
public sealed class Subnet : IEquatable<Subnet>
{
    public IPAddress NetworkAddress { get; }
    public int PrefixLength { get; }
    public AddressFamily Family => NetworkAddress.AddressFamily;

    private Subnet(IPAddress networkAddress, int prefixLength)
    {
        NetworkAddress = networkAddress;
        PrefixLength = prefixLength;
    }

    public static Subnet Parse(string cidr)
        => TryParse(cidr, out var subnet) ? subnet! : throw new FormatException($"'{cidr}' is not valid CIDR.");

    public static bool TryParse(string? cidr, out Subnet? subnet)
    {
        subnet = null;
        if (string.IsNullOrWhiteSpace(cidr)) return false;

        var slash = cidr.IndexOf('/');
        // A bare IP is treated as a /32 (IPv4) or /128 (IPv6) host route.
        var addressPart = slash < 0 ? cidr : cidr[..slash];
        if (!IPAddress.TryParse(addressPart, out var address)) return false;

        var maxPrefix = address.AddressFamily == AddressFamily.InterNetwork ? 32 : 128;
        var prefix = maxPrefix;
        if (slash >= 0 && (!int.TryParse(cidr[(slash + 1)..], out prefix) || prefix < 0 || prefix > maxPrefix))
            return false;

        subnet = new Subnet(MaskToPrefix(address, prefix), prefix);
        return true;
    }

    public bool Contains(IPAddress address)
    {
        if (address.AddressFamily != Family) return false;
        return MaskToPrefix(address, PrefixLength).Equals(NetworkAddress);
    }

    /// <summary>True when this subnet fully contains <paramref name="other"/> (equal or more specific).</summary>
    public bool Contains(Subnet other)
        => other.Family == Family && other.PrefixLength >= PrefixLength && Contains(other.NetworkAddress);

    /// <summary>Number of usable host addresses (IPv4). Excludes network/broadcast for prefixes ≤ 30.</summary>
    public long UsableHostCount
    {
        get
        {
            if (Family != AddressFamily.InterNetwork) return -1;
            var total = 1L << (32 - PrefixLength);
            return PrefixLength >= 31 ? total : total - 2;
        }
    }

    /// <summary>
    /// Enumerates usable host addresses (IPv4 only). /31 and /32 yield every address; wider
    /// networks omit the network and broadcast addresses. Bounded by <paramref name="maxHosts"/>.
    /// </summary>
    public IEnumerable<IPAddress> EnumerateHosts(int maxHosts = 65536)
    {
        if (Family != AddressFamily.InterNetwork)
            throw new NotSupportedException("Host enumeration is only supported for IPv4 subnets.");

        var network = ToUInt32(NetworkAddress);
        var total = 1L << (32 - PrefixLength);
        var includeEdges = PrefixLength >= 31;

        var first = includeEdges ? network : network + 1;
        var last = includeEdges ? network + (uint)total - 1 : network + (uint)total - 2;

        var emitted = 0;
        for (var addr = first; addr <= last && emitted < maxHosts; addr++)
        {
            emitted++;
            yield return FromUInt32(addr);
            if (addr == uint.MaxValue) break; // guard against overflow wrap
        }
    }

    private static IPAddress MaskToPrefix(IPAddress address, int prefixLength)
    {
        var bytes = address.GetAddressBytes();
        var fullBytes = prefixLength / 8;
        var remainingBits = prefixLength % 8;

        for (var i = fullBytes; i < bytes.Length; i++)
        {
            if (i == fullBytes && remainingBits != 0)
                bytes[i] &= (byte)(0xFF << (8 - remainingBits));
            else if (i > fullBytes || remainingBits == 0)
                bytes[i] = 0;
        }

        return new IPAddress(bytes);
    }

    private static uint ToUInt32(IPAddress address)
    {
        var b = address.GetAddressBytes();
        return ((uint)b[0] << 24) | ((uint)b[1] << 16) | ((uint)b[2] << 8) | b[3];
    }

    private static IPAddress FromUInt32(uint value)
        => new(new[] { (byte)(value >> 24), (byte)(value >> 16), (byte)(value >> 8), (byte)value });

    public bool Equals(Subnet? other)
        => other is not null && PrefixLength == other.PrefixLength && NetworkAddress.Equals(other.NetworkAddress);

    public override bool Equals(object? obj) => Equals(obj as Subnet);
    public override int GetHashCode() => HashCode.Combine(NetworkAddress, PrefixLength);
    public override string ToString() => $"{NetworkAddress}/{PrefixLength}";
}
