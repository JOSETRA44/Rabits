using Rabits.Application.Abstractions;
using Rabits.Domain.Auditing;
using Rabits.Domain.Engagement;
using Rabits.Domain.Networking;
using Rabits.Domain.Operations;

namespace Rabits.Tests;

internal sealed class FixedClock : IClock
{
    public FixedClock(DateTimeOffset now) => Now = now;
    public DateTimeOffset Now { get; }
}

internal sealed class FakeScopePolicy : IScopePolicy
{
    public FakeScopePolicy(EngagementScope? scope) => Current = scope;
    public EngagementScope? Current { get; }
}

internal sealed class StubWirelessScanner : IWirelessScanner
{
    private readonly IReadOnlyList<WirelessNetwork> _networks;
    public StubWirelessScanner(IReadOnlyList<WirelessNetwork> networks) => _networks = networks;
    public bool IsSupported => true;
    public Task<IReadOnlyList<WirelessNetwork>> ScanAsync(CancellationToken cancellationToken = default)
        => Task.FromResult(_networks);
}

/// <summary>In-memory audit log that mirrors the real hash-chaining, for asserting gate behaviour.</summary>
internal sealed class InMemoryAuditLog : IAuditLog
{
    private readonly List<AuditEntry> _entries = new();
    private readonly IClock _clock;
    private string _lastHash = AuditEntry.GenesisHash;

    public InMemoryAuditLog(IClock clock) => _clock = clock;

    public IReadOnlyList<AuditEntry> Entries => _entries;

    public Task<AuditEntry> RecordAsync(RabitsOperation operation, AuditOutcome outcome, string detail,
        CancellationToken cancellationToken = default)
    {
        var entry = AuditEntry.Create(_entries.Count + 1, _clock.Now, "test", operation, outcome, detail, _lastHash);
        _entries.Add(entry);
        _lastHash = entry.Hash;
        return Task.FromResult(entry);
    }

    public Task<IReadOnlyList<AuditEntry>> ReadAllAsync(CancellationToken cancellationToken = default)
        => Task.FromResult<IReadOnlyList<AuditEntry>>(_entries);

    public Task<bool> VerifyAsync(CancellationToken cancellationToken = default) => Task.FromResult(true);
}
