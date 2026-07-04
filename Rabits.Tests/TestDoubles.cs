using System.Net;
using Rabits.Application.Abstractions;
using Rabits.Domain.Auditing;
using Rabits.Domain.Engagement;
using Rabits.Domain.Networking;
using Rabits.Domain.Operations;
using Rabits.Domain.Recon;

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

internal sealed class FakeHostProbe : IHostProbe
{
    private readonly HashSet<string> _up;
    public FakeHostProbe(params string[] upAddresses) => _up = new HashSet<string>(upAddresses);

    public Task<HostProbeResult> ProbeAsync(IPAddress address, CancellationToken cancellationToken = default)
        => Task.FromResult(_up.Contains(address.ToString())
            ? new HostProbeResult(HostStatus.Up, TimeSpan.FromMilliseconds(1), DiscoveryMethod.IcmpEcho)
            : HostProbeResult.Down);
}

/// <summary>Resolves a MAC only for the addresses declared alive, mirroring real ARP behaviour.</summary>
internal sealed class FakeArpResolver : IArpResolver
{
    private readonly MacAddress _mac;
    private readonly HashSet<string> _reachable;

    public FakeArpResolver(MacAddress mac, params string[] reachable)
    {
        _mac = mac;
        _reachable = new HashSet<string>(reachable);
    }

    public Task<MacAddress?> ResolveAsync(IPAddress address, CancellationToken cancellationToken = default)
        => Task.FromResult(_reachable.Contains(address.ToString()) ? _mac : (MacAddress?)null);
}

internal sealed class StubOuiLookup : IOuiVendorLookup
{
    public int EntryCount => 0;
    public string? Lookup(MacAddress mac) => "TestVendor";
}

internal sealed class StubPortScanner : IPortScanner
{
    public Task<IReadOnlyList<DiscoveredPort>> ScanAsync(
        IPAddress address, IReadOnlyList<int> ports, CancellationToken cancellationToken = default)
        => Task.FromResult<IReadOnlyList<DiscoveredPort>>(Array.Empty<DiscoveredPort>());
}

internal sealed class StubReverseDns : IReverseDnsResolver
{
    public Task<string?> ResolveAsync(IPAddress address, CancellationToken cancellationToken = default)
        => Task.FromResult<string?>(null);
}

internal sealed class FakeDnsResolver : IDnsResolver
{
    private readonly Func<string, DnsRecordType, IReadOnlyList<DnsRecord>> _resolve;
    public FakeDnsResolver(Func<string, DnsRecordType, IReadOnlyList<DnsRecord>> resolve) => _resolve = resolve;

    public Task<IReadOnlyList<DnsRecord>> QueryAsync(string name, DnsRecordType type, CancellationToken cancellationToken = default)
        => Task.FromResult(_resolve(name, type));
}

internal sealed class FakeWordlist : ISubdomainWordlist
{
    public FakeWordlist(params string[] labels) => Labels = labels;
    public IReadOnlyList<string> Labels { get; }
}

internal sealed class FakeWebProbe : IWebProbe
{
    private readonly WebEndpointInfo _info;
    public FakeWebProbe(WebEndpointInfo info) => _info = info;
    public Task<WebEndpointInfo> InspectAsync(Uri url, CancellationToken cancellationToken = default)
        => Task.FromResult(_info);
}
