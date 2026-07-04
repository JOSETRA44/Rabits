using Microsoft.Extensions.Logging.Abstractions;
using Rabits.Application.Security;
using Rabits.Application.Wireless;
using Rabits.Domain.Auditing;
using Rabits.Domain.Networking;

namespace Rabits.Tests.Application;

public class ScanWirelessNetworksHandlerTests
{
    private static WirelessNetwork Net(string ssid, int dbm) => new()
    {
        Ssid = ssid,
        Bssid = MacAddress.Parse("00:11:22:33:44:55"),
        Rssi = SignalStrength.FromDbm(dbm),
        Channel = NetworkChannel.FromNumber(6),
        Encryption = EncryptionType.Wpa2,
    };

    [Fact]
    public async Task Returns_networks_ordered_by_signal_strength_descending()
    {
        var scanner = new StubWirelessScanner(new[] { Net("weak", -80), Net("strong", -40), Net("mid", -60) });
        var clock = new FixedClock(DateTimeOffset.UnixEpoch);
        var audit = new InMemoryAuditLog(clock);
        var guard = new AuthorizationGuard(new FakeScopePolicy(null), clock, audit, NullLogger<AuthorizationGuard>.Instance);
        var handler = new ScanWirelessNetworksHandler(scanner, guard, audit);

        var result = await handler.HandleAsync();

        Assert.Equal(new[] { "strong", "mid", "weak" }, result.Select(n => n.Ssid));
    }

    [Fact]
    public async Task Records_a_completed_audit_entry()
    {
        var scanner = new StubWirelessScanner(new[] { Net("a", -50) });
        var clock = new FixedClock(DateTimeOffset.UnixEpoch);
        var audit = new InMemoryAuditLog(clock);
        var guard = new AuthorizationGuard(new FakeScopePolicy(null), clock, audit, NullLogger<AuthorizationGuard>.Instance);
        var handler = new ScanWirelessNetworksHandler(scanner, guard, audit);

        await handler.HandleAsync();

        Assert.Contains(audit.Entries, e => e.Outcome == AuditOutcome.Completed && e.OperationName == "wifi.scan");
    }
}
