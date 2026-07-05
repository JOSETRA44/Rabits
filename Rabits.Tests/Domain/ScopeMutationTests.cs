using Rabits.Domain.Engagement;
using Rabits.Domain.Operations;

namespace Rabits.Tests.Domain;

public class ScopeMutationTests
{
    [Theory]
    [InlineData("10.0.0.0/24", TargetType.Cidr)]
    [InlineData("192.168.1.5", TargetType.Cidr)]
    [InlineData("example.com", TargetType.Domain)]
    [InlineData("*.example.com", TargetType.Domain)]
    [InlineData("AA:BB:CC:DD:EE:FF", TargetType.Bssid)]
    [InlineData("CorpWifi", TargetType.Ssid)]
    public void ForTarget_infers_the_rule_type(string target, TargetType expected)
        => Assert.Equal(expected, ScopeRule.ForTarget(target).Type);

    [Fact]
    public void WithRule_adds_and_deduplicates()
    {
        var scope = new EngagementScope { Name = "e" };
        var once = scope.WithRule(ScopeRule.Domain("a.com"));
        var twice = once.WithRule(ScopeRule.Domain("a.com"));

        Assert.Single(once.Rules);
        Assert.Single(twice.Rules);
    }

    [Fact]
    public void WithoutRule_removes_by_pattern()
    {
        var scope = new EngagementScope { Name = "e", Rules = new[] { ScopeRule.Domain("a.com"), ScopeRule.Domain("b.com") } };
        var updated = scope.WithoutRule("a.com");
        Assert.Single(updated.Rules);
        Assert.Equal("b.com", updated.Rules[0].Pattern);
    }

    [Fact]
    public void WithMaxClassification_raises_the_ceiling()
    {
        var scope = new EngagementScope { Name = "e" }.WithMaxClassification(OperationClassification.Intrusive);
        Assert.Equal(OperationClassification.Intrusive, scope.MaxClassification);
    }
}
