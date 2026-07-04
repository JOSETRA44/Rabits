using Microsoft.Extensions.Logging.Abstractions;
using Rabits.Application.Hosts;
using Rabits.Application.Security;
using Rabits.Domain.Auditing;
using Rabits.Domain.Engagement;
using Rabits.Domain.Networking;
using Rabits.Domain.Operations;

namespace Rabits.Tests.Application;

public class DiscoverHostsHandlerTests
{
    private static readonly DateTimeOffset Now = new(2026, 7, 3, 12, 0, 0, TimeSpan.Zero);

    private static DiscoverHostsHandler Build(EngagementScope? scope, out InMemoryAuditLog audit, params string[] upHosts)
    {
        var clock = new FixedClock(Now);
        audit = new InMemoryAuditLog(clock);
        var guard = new AuthorizationGuard(new FakeScopePolicy(scope), clock, audit, NullLogger<AuthorizationGuard>.Instance);
        return new DiscoverHostsHandler(
            new FakeHostProbe(upHosts),
            new FakeArpResolver(MacAddress.Parse("00:0C:29:11:22:33"), upHosts),
            new StubOuiLookup(),
            new StubPortScanner(),
            new StubReverseDns(),
            guard,
            audit);
    }

    private static EngagementScope ScopeFor(string cidr) => new()
    {
        Name = "lab",
        Rules = new[] { ScopeRule.Cidr(cidr) },
        MaxClassification = OperationClassification.Active,
    };

    [Fact]
    public async Task Discovery_is_refused_when_the_range_is_not_in_scope()
    {
        var handler = Build(scope: null, out var audit, "10.0.0.1");
        var request = new HostDiscoveryRequest { Target = "10.0.0.0/29" };

        await Assert.ThrowsAsync<OutOfScopeException>(() => handler.HandleAsync(request));
        Assert.Contains(audit.Entries, e => e.Outcome == AuditOutcome.Denied);
    }

    [Fact]
    public async Task Returns_only_up_hosts_ordered_by_ip_and_audits_completion()
    {
        var handler = Build(ScopeFor("10.0.0.0/24"), out var audit, "10.0.0.6", "10.0.0.1");
        var request = new HostDiscoveryRequest { Target = "10.0.0.0/29" };

        var hosts = await handler.HandleAsync(request);

        Assert.Equal(new[] { "10.0.0.1", "10.0.0.6" }, hosts.Select(h => h.Address.ToString()));
        Assert.All(hosts, h => Assert.Equal(HostStatus.Up, h.Status));
        Assert.Equal("TestVendor", hosts[0].Vendor);
        Assert.Contains(audit.Entries, e => e.Outcome == AuditOutcome.Completed && e.OperationName == "host.discover");
    }

    [Fact]
    public async Task Invalid_target_throws()
    {
        var handler = Build(ScopeFor("10.0.0.0/24"), out _, "10.0.0.1");
        await Assert.ThrowsAsync<ArgumentException>(
            () => handler.HandleAsync(new HostDiscoveryRequest { Target = "not-an-ip" }));
    }
}
