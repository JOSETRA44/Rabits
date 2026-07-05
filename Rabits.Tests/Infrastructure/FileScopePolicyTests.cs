using Microsoft.Extensions.Logging.Abstractions;
using Rabits.Application.Security;
using Rabits.Domain.Engagement;
using Rabits.Domain.Operations;
using Rabits.Infrastructure.Engagement;

namespace Rabits.Tests.Infrastructure;

public class FileScopePolicyTests : IDisposable
{
    private readonly string _path = Path.Combine(Path.GetTempPath(), $"rabits-scope-{Guid.NewGuid():N}.json");

    private JsonScopePolicy NewPolicy() => new(_path, NullLogger<JsonScopePolicy>.Instance);

    [Fact]
    public void Authorize_creates_persists_and_raises_classification()
    {
        var policy = NewPolicy();
        Assert.Null(policy.Current);

        var scope = policy.Authorize(ScopeRule.Cidr("127.0.0.1"), OperationClassification.Intrusive);

        Assert.True(File.Exists(_path));
        Assert.Equal(OperationClassification.Intrusive, scope.MaxClassification);
        Assert.Contains(policy.Current!.Rules, r => r.Pattern == "127.0.0.1");
    }

    [Fact]
    public void Current_hot_reloads_external_edits()
    {
        var policy = NewPolicy();
        policy.Authorize(ScopeRule.Cidr("10.0.0.0/24"));

        File.WriteAllText(_path, "{\"name\":\"external\",\"maxClassification\":\"Active\",\"rules\":[{\"type\":\"Domain\",\"pattern\":\"b.com\"}]}");
        File.SetLastWriteTimeUtc(_path, DateTime.UtcNow.AddSeconds(5)); // force change detection deterministically

        Assert.Equal("external", policy.Current!.Name);
        Assert.Contains(policy.Current!.Rules, r => r.Pattern == "b.com");
    }

    [Fact]
    public async Task Authorization_added_mid_session_takes_effect_immediately()
    {
        var policy = NewPolicy();
        var clock = new FixedClock(DateTimeOffset.UnixEpoch);
        var audit = new InMemoryAuditLog(clock);
        var guard = new AuthorizationGuard(policy, clock, audit, NullLogger<AuthorizationGuard>.Instance);
        var operation = RabitsOperation.Active("test.op", "127.0.0.1");

        // Refused: nothing is authorized yet.
        await Assert.ThrowsAsync<OutOfScopeException>(() => guard.AuthorizeAsync(operation));

        // Operator authorizes the target mid-session — no restart.
        policy.Authorize(ScopeRule.Cidr("127.0.0.1"), OperationClassification.Intrusive);

        // Now the very same guard permits it.
        await guard.AuthorizeAsync(operation); // does not throw
    }

    public void Dispose()
    {
        if (File.Exists(_path)) File.Delete(_path);
    }
}
