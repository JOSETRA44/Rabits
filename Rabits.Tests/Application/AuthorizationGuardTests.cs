using Microsoft.Extensions.Logging.Abstractions;
using Rabits.Application.Security;
using Rabits.Domain.Auditing;
using Rabits.Domain.Engagement;
using Rabits.Domain.Operations;

namespace Rabits.Tests.Application;

public class AuthorizationGuardTests
{
    private static readonly DateTimeOffset Now = new(2026, 7, 3, 12, 0, 0, TimeSpan.Zero);

    private static (AuthorizationGuard guard, InMemoryAuditLog audit) Build(EngagementScope? scope)
    {
        var clock = new FixedClock(Now);
        var audit = new InMemoryAuditLog(clock);
        var guard = new AuthorizationGuard(new FakeScopePolicy(scope), clock, audit, NullLogger<AuthorizationGuard>.Instance);
        return (guard, audit);
    }

    private static EngagementScope ScopeFor(params ScopeRule[] rules) => new()
    {
        Name = "test-engagement",
        Rules = rules,
        StartsAt = Now.AddHours(-1),
        EndsAt = Now.AddHours(1),
        MaxClassification = OperationClassification.Intrusive,
    };

    [Fact]
    public async Task Passive_operations_are_always_allowed_even_without_a_scope()
    {
        var (guard, audit) = Build(scope: null);
        await guard.AuthorizeAsync(RabitsOperation.Passive("wifi.scan"));
        Assert.Empty(audit.Entries); // passive is recorded by the use case, not the gate
    }

    [Fact]
    public async Task Active_operation_is_denied_when_no_scope_is_loaded()
    {
        var (guard, audit) = Build(scope: null);
        var op = RabitsOperation.Active("port.scan", "10.0.0.5");

        await Assert.ThrowsAsync<OutOfScopeException>(() => guard.AuthorizeAsync(op));
        Assert.Single(audit.Entries);
        Assert.Equal(AuditOutcome.Denied, audit.Entries[0].Outcome);
    }

    [Fact]
    public async Task Active_operation_in_scope_is_authorized_and_audited()
    {
        var (guard, audit) = Build(ScopeFor(ScopeRule.Cidr("10.0.0.0/24")));
        var op = RabitsOperation.Active("port.scan", "10.0.0.5");

        await guard.AuthorizeAsync(op);
        Assert.Single(audit.Entries);
        Assert.Equal(AuditOutcome.Authorized, audit.Entries[0].Outcome);
    }

    [Fact]
    public async Task Active_operation_out_of_scope_is_denied()
    {
        var (guard, _) = Build(ScopeFor(ScopeRule.Cidr("10.0.0.0/24")));
        var op = RabitsOperation.Active("port.scan", "192.168.1.5");

        await Assert.ThrowsAsync<OutOfScopeException>(() => guard.AuthorizeAsync(op));
    }

    [Fact]
    public async Task Operation_outside_the_time_window_is_denied()
    {
        var expired = new EngagementScope
        {
            Name = "expired",
            Rules = new[] { ScopeRule.Cidr("10.0.0.0/24") },
            EndsAt = Now.AddHours(-1),
        };
        var (guard, _) = Build(expired);

        await Assert.ThrowsAsync<OutOfScopeException>(
            () => guard.AuthorizeAsync(RabitsOperation.Active("port.scan", "10.0.0.5")));
    }
}
