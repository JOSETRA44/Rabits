using Microsoft.Extensions.Logging.Abstractions;
using Rabits.Application.Recon;
using Rabits.Application.Security;
using Rabits.Domain.Auditing;
using Rabits.Domain.Engagement;
using Rabits.Domain.Operations;
using Rabits.Domain.Recon;

namespace Rabits.Tests.Application;

public class ReconHandlerTests
{
    private static AuthorizationGuard Guard(EngagementScope? scope, out InMemoryAuditLog audit)
    {
        var clock = new FixedClock(DateTimeOffset.UnixEpoch);
        audit = new InMemoryAuditLog(clock);
        return new AuthorizationGuard(new FakeScopePolicy(scope), clock, audit, NullLogger<AuthorizationGuard>.Instance);
    }

    [Fact]
    public async Task Dns_recon_aggregates_records_and_audits()
    {
        var resolver = new FakeDnsResolver((name, type) => type == DnsRecordType.A
            ? new[] { new DnsRecord(DnsRecordType.A, "93.184.216.34", 300) }
            : Array.Empty<DnsRecord>());
        var handler = new DnsReconHandler(resolver, Guard(scope: null, out var audit), audit);

        var records = await handler.HandleAsync("example.com", new[] { DnsRecordType.A, DnsRecordType.MX });

        Assert.Single(records);
        Assert.Equal("93.184.216.34", records[0].Value);
        Assert.Contains(audit.Entries, e => e.Outcome == AuditOutcome.Completed && e.OperationName == "dns.lookup");
    }

    [Fact]
    public async Task Subdomain_enumeration_returns_only_resolving_labels()
    {
        var resolver = new FakeDnsResolver((name, type) =>
            name == "www.example.com" && type == DnsRecordType.A
                ? new[] { new DnsRecord(DnsRecordType.A, "93.184.216.34", 300) }
                : Array.Empty<DnsRecord>());
        var handler = new EnumerateSubdomainsHandler(
            resolver, new FakeWordlist("www", "admin", "mail"), Guard(scope: null, out var audit), audit);

        var found = await handler.HandleAsync("example.com");

        var hit = Assert.Single(found);
        Assert.Equal("www.example.com", hit.Name);
    }

    [Fact]
    public async Task Web_inspection_is_scope_gated()
    {
        var info = new WebEndpointInfo { Url = new Uri("https://example.com/"), StatusCode = 200 };
        var guard = Guard(scope: null, out var audit);
        var handler = new InspectWebEndpointHandler(new FakeWebProbe(info), guard, audit);

        await Assert.ThrowsAsync<OutOfScopeException>(() => handler.HandleAsync("https://example.com"));
    }

    [Fact]
    public async Task Web_inspection_succeeds_when_host_is_in_scope()
    {
        var info = new WebEndpointInfo { Url = new Uri("https://example.com/"), StatusCode = 200 };
        var scope = new EngagementScope
        {
            Name = "web",
            Rules = new[] { ScopeRule.Domain("example.com") },
            MaxClassification = OperationClassification.Active,
        };
        var guard = Guard(scope, out var audit);
        var handler = new InspectWebEndpointHandler(new FakeWebProbe(info), guard, audit);

        var result = await handler.HandleAsync("https://example.com");

        Assert.Equal(200, result.StatusCode);
        Assert.Contains(audit.Entries, e => e.Outcome == AuditOutcome.Completed && e.OperationName == "web.inspect");
    }
}
