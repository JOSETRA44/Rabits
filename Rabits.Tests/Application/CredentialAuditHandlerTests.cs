using Microsoft.Extensions.Logging.Abstractions;
using Rabits.Application.Auth;
using Rabits.Application.Security;
using Rabits.Domain.Auditing;
using Rabits.Domain.Auth;
using Rabits.Domain.Engagement;
using Rabits.Domain.Operations;

namespace Rabits.Tests.Application;

public class CredentialAuditHandlerTests
{
    private static CredentialAuditHandler Build(EngagementScope? scope, out InMemoryAuditLog audit, string validPassword = "letmein")
    {
        var clock = new FixedClock(DateTimeOffset.UnixEpoch);
        audit = new InMemoryAuditLog(clock);
        var policy = new FakeScopePolicy(scope);
        var guard = new AuthorizationGuard(policy, clock, audit, NullLogger<AuthorizationGuard>.Instance);
        return new CredentialAuditHandler(new FakeAuthProbe("admin", validPassword), guard, audit, policy);
    }

    private static EngagementScope Scope(OperationClassification max) => new()
    {
        Name = "engagement",
        Rules = new[] { ScopeRule.Domain("target.test") },
        MaxClassification = max,
    };

    private static CredentialAuditRequest Request() => new()
    {
        Target = new AuthTarget { Protocol = AuthProtocol.HttpForm, Url = new Uri("https://target.test/login") },
        Usernames = new[] { "admin" },
        Passwords = new[] { "wrong1", "wrong2", "letmein", "wrong3" },
    };

    [Fact]
    public async Task Intrusive_audit_is_denied_when_the_engagement_only_permits_active()
    {
        var handler = Build(Scope(OperationClassification.Active), out var audit);
        await Assert.ThrowsAsync<OutOfScopeException>(() => handler.HandleAsync(Request()));
        Assert.Contains(audit.Entries, e => e.Outcome == AuditOutcome.Denied);
    }

    [Fact]
    public async Task Audit_is_denied_when_the_host_is_out_of_scope()
    {
        var handler = Build(scope: null, out _);
        await Assert.ThrowsAsync<OutOfScopeException>(() => handler.HandleAsync(Request()));
    }

    [Fact]
    public async Task Finds_the_valid_credential_when_intrusive_is_authorized()
    {
        var handler = Build(Scope(OperationClassification.Intrusive), out var audit);

        var summary = await handler.HandleAsync(Request());

        Assert.True(summary.AnySuccess);
        Assert.Contains(summary.Successes, c => c.Username == "admin" && c.Password == "letmein");
        Assert.True(summary.StoppedEarly);
        Assert.Contains(audit.Entries, e => e.Detail.Contains("VALID credential"));
        Assert.Contains(audit.Entries, e => e.OperationName == "auth.http" && e.Outcome == AuditOutcome.Authorized);
    }

    [Fact]
    public async Task Reports_no_success_when_the_password_is_not_in_the_list()
    {
        var handler = Build(Scope(OperationClassification.Intrusive), out _, validPassword: "not-in-list");
        var summary = await handler.HandleAsync(Request());
        Assert.False(summary.AnySuccess);
    }

    [Fact]
    public async Task Respects_the_max_attempts_cap()
    {
        var handler = Build(Scope(OperationClassification.Intrusive), out _, validPassword: "never");
        var request = Request() with { Passwords = Enumerable.Range(0, 100).Select(i => $"pw{i}").ToList(), MaxAttempts = 10 };

        var summary = await handler.HandleAsync(request);

        Assert.True(summary.Attempted <= 10);
    }
}
