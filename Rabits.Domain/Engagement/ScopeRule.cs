using System.Net;
using System.Net.Sockets;
using Rabits.Domain.Networking;

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
        if (!Subnet.TryParse(Pattern, out var ruleNetwork) || ruleNetwork is null)
            return false;

        // A CIDR target must be *fully contained* in the rule (no half-in-scope ranges); a bare
        // IP target is matched as a single address.
        if (target.Contains('/'))
            return Subnet.TryParse(target, out var requested) && requested is not null && ruleNetwork.Contains(requested);

        return IPAddress.TryParse(target, out var ip) && ruleNetwork.Contains(ip);
    }

    public static ScopeRule Cidr(string cidr) => new(TargetType.Cidr, cidr);
    public static ScopeRule Domain(string domain) => new(TargetType.Domain, domain);
    public static ScopeRule Ssid(string ssid) => new(TargetType.Ssid, ssid);
    public static ScopeRule Bssid(string bssid) => new(TargetType.Bssid, bssid);

    /// <summary>
    /// Infers the rule type from a free-form target (used when an operator authorizes a target
    /// conversationally): CIDR/IP → Cidr, MAC → Bssid, hostname/domain → Domain, otherwise SSID.
    /// </summary>
    public static ScopeRule ForTarget(string target)
    {
        var value = target.Trim();
        if (value.Length == 0) return Ssid("*");

        if (value.Contains('/') && Subnet.TryParse(value, out _)) return Cidr(value);
        if (IPAddress.TryParse(value, out _)) return Cidr(value);        // bare IP → host route
        if (MacAddress.TryParse(value, out _)) return Bssid(value);
        if (LooksLikeDomain(value)) return Domain(value);
        return Ssid(value);
    }

    private static bool LooksLikeDomain(string value)
    {
        var host = value.StartsWith("*.", StringComparison.Ordinal) ? value[2..] : value;
        if (!host.Contains('.')) return false;
        foreach (var c in host)
            if (!(char.IsLetterOrDigit(c) || c is '.' or '-' or '_')) return false;
        var lastLabel = host[(host.LastIndexOf('.') + 1)..];
        return lastLabel.Length >= 2 && lastLabel.All(char.IsLetter);
    }
}
