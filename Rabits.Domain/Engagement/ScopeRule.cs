using System.Net;
using System.Net.Sockets;

namespace Rabits.Domain.Engagement;

/// <summary>The kind of target a <see cref="ScopeRule"/> matches against.</summary>
public enum TargetType
{
    /// <summary>An IPv4/IPv6 network in CIDR notation, e.g. "10.0.0.0/24".</summary>
    Cidr,
    /// <summary>A single IP address.</summary>
    IpAddress,
    /// <summary>A DNS domain; a leading "*." matches any subdomain.</summary>
    Domain,
    /// <summary>A wireless SSID (case-insensitive); "*" matches any.</summary>
    Ssid,
    /// <summary>A specific BSSID / MAC address.</summary>
    Bssid,
}

/// <summary>
/// A single authorization rule inside an <see cref="EngagementScope"/>: it declares one target
/// (or range) that active operations are permitted to touch.
/// </summary>
public sealed record ScopeRule(TargetType Type, string Pattern)
{
    /// <summary>True if <paramref name="target"/> falls within this rule.</summary>
    public bool Matches(string target)
    {
        if (string.IsNullOrWhiteSpace(target)) return false;

        return Type switch
        {
            TargetType.Cidr => MatchesCidr(target),
            TargetType.IpAddress => IPAddress.TryParse(target, out var ip)
                                    && IPAddress.TryParse(Pattern, out var self) && ip.Equals(self),
            TargetType.Domain => MatchesDomain(target),
            TargetType.Ssid => Pattern == "*" || string.Equals(Pattern, target, StringComparison.OrdinalIgnoreCase),
            TargetType.Bssid => string.Equals(Pattern, target, StringComparison.OrdinalIgnoreCase),
            _ => false,
        };
    }

    private bool MatchesDomain(string target)
    {
        var host = target.Trim().TrimEnd('.').ToLowerInvariant();
        if (Pattern.StartsWith("*.", StringComparison.Ordinal))
        {
            var suffix = Pattern[1..].ToLowerInvariant(); // ".example.com"
            return host.EndsWith(suffix, StringComparison.Ordinal)
                   || host == suffix.TrimStart('.');
        }
        return host == Pattern.Trim().TrimEnd('.').ToLowerInvariant();
    }

    private bool MatchesCidr(string target)
    {
        if (!IPAddress.TryParse(target, out var ip)) return false;

        var slash = Pattern.IndexOf('/');
        if (slash < 0) return false;
        if (!IPAddress.TryParse(Pattern[..slash], out var network)) return false;
        if (!int.TryParse(Pattern[(slash + 1)..], out var prefix)) return false;
        if (ip.AddressFamily != network.AddressFamily) return false;

        var ipBytes = ip.GetAddressBytes();
        var netBytes = network.GetAddressBytes();
        if (prefix < 0 || prefix > ipBytes.Length * 8) return false;

        var fullBytes = prefix / 8;
        for (var i = 0; i < fullBytes; i++)
            if (ipBytes[i] != netBytes[i]) return false;

        var remainingBits = prefix % 8;
        if (remainingBits == 0) return true;

        var mask = (byte)(0xFF << (8 - remainingBits));
        return (ipBytes[fullBytes] & mask) == (netBytes[fullBytes] & mask);
    }

    public static ScopeRule Cidr(string cidr) => new(TargetType.Cidr, cidr);
    public static ScopeRule Domain(string domain) => new(TargetType.Domain, domain);
    public static ScopeRule Ssid(string ssid) => new(TargetType.Ssid, ssid);
    public static ScopeRule Bssid(string bssid) => new(TargetType.Bssid, bssid);
}
