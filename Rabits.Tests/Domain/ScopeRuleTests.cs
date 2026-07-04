using Rabits.Domain.Engagement;

namespace Rabits.Tests.Domain;

public class ScopeRuleTests
{
    [Theory]
    [InlineData("10.0.0.0/24", "10.0.0.5", true)]
    [InlineData("10.0.0.0/24", "10.0.1.5", false)]
    [InlineData("192.168.1.0/28", "192.168.1.10", true)]
    [InlineData("192.168.1.0/28", "192.168.1.20", false)]
    public void Cidr_rule_matches_addresses_in_range(string cidr, string target, bool expected)
        => Assert.Equal(expected, ScopeRule.Cidr(cidr).Matches(target));

    [Theory]
    [InlineData("*.example.com", "app.example.com", true)]
    [InlineData("*.example.com", "example.com", true)]
    [InlineData("*.example.com", "example.org", false)]
    [InlineData("example.com", "example.com", true)]
    [InlineData("example.com", "sub.example.com", false)]
    public void Domain_rule_handles_wildcards(string pattern, string target, bool expected)
        => Assert.Equal(expected, ScopeRule.Domain(pattern).Matches(target));

    [Theory]
    [InlineData("*", "AnySSID", true)]
    [InlineData("Corp", "corp", true)]
    [InlineData("Corp", "Guest", false)]
    public void Ssid_rule_is_case_insensitive_with_wildcard(string pattern, string target, bool expected)
        => Assert.Equal(expected, ScopeRule.Ssid(pattern).Matches(target));
}
