using Microsoft.Extensions.Logging.Abstractions;
using Rabits.Application.Security;
using Rabits.Domain.Auditing;
using Rabits.Domain.Operations;

namespace Rabits.Tests.Application;

public class GodModeTests
{
    private static AuthorizationGuard Build(bool bypass, out InMemoryAuditLog audit)
    {
        var clock = new FixedClock(DateTimeOffset.UnixEpoch);
        audit = new InMemoryAuditLog(clock);
        // No scope loaded — normally every active/intrusive op is denied.
        return new AuthorizationGuard(new FakeScopePolicy(null), clock, audit,
            NullLogger<AuthorizationGuard>.Instance, new AuthorizationOptions { BypassScope = bypass });
    }

    [Fact]
    public async Task Bypass_allows_an_intrusive_op_that_would_otherwise_be_denied()
    {
        var guard = Build(bypass: true, out _);
        // Would throw OutOfScopeException without God Mode (no scope loaded).
        await guard.AuthorizeAsync(RabitsOperation.Intrusive("auth.http", "example.com"));
    }

    [Fact]
    public async Task Bypass_still_records_an_audit_entry()
    {
        var guard = Build(bypass: true, out var audit);
        await guard.AuthorizeAsync(RabitsOperation.Active("port.scan", "10.0.0.5"));

        var entry = Assert.Single(audit.Entries);
        Assert.Equal(AuditOutcome.Authorized, entry.Outcome);
        Assert.Contains("GOD MODE", entry.Detail);
    }

    [Fact]
    public async Task Without_bypass_the_gate_still_denies_out_of_scope_ops()
    {
        var guard = Build(bypass: false, out _);
        await Assert.ThrowsAsync<Rabits.Domain.Engagement.OutOfScopeException>(
            () => guard.AuthorizeAsync(RabitsOperation.Active("port.scan", "10.0.0.5")));
    }
}
