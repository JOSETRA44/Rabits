using Microsoft.Extensions.Logging.Abstractions;
using Rabits.Application.Security;
using Rabits.Application.Traffic;
using Rabits.Domain.Auditing;
using Rabits.Domain.Traffic;

namespace Rabits.Tests.Application;

public class TrafficTests
{
    private static AuthorizationGuard PassiveGuard(out InMemoryAuditLog audit)
    {
        var clock = new FixedClock(DateTimeOffset.UnixEpoch);
        audit = new InMemoryAuditLog(clock);
        return new AuthorizationGuard(new FakeScopePolicy(null), clock, audit, NullLogger<AuthorizationGuard>.Instance);
    }

    [Fact]
    public void Aggregator_counts_totals_bytes_and_protocols()
    {
        var aggregator = new TrafficAggregator();
        aggregator.Add(TestPackets.Make(TrafficProtocol.Tcp, 100));
        aggregator.Add(TestPackets.Make(TrafficProtocol.Tcp, 200));
        aggregator.Add(TestPackets.Make(TrafficProtocol.Udp, 50));
        aggregator.Add(TestPackets.Make(TrafficProtocol.Dns, 80));

        var stats = aggregator.Snapshot();

        Assert.Equal(4, stats.TotalPackets);
        Assert.Equal(430, stats.TotalBytes);
        Assert.Equal(2, stats.CountOf(TrafficProtocol.Tcp));
        Assert.Equal(1, stats.CountOf(TrafficProtocol.Udp));
        Assert.Equal(1, stats.CountOf(TrafficProtocol.Dns));
        Assert.True(stats.PacketsPerSecond >= 0);
    }

    [Fact]
    public void Aggregator_reset_clears_counters()
    {
        var aggregator = new TrafficAggregator();
        aggregator.Add(TestPackets.Make(TrafficProtocol.Tcp));
        aggregator.Reset();
        Assert.Equal(0, aggregator.Snapshot().TotalPackets);
    }

    [Fact]
    public async Task Capture_streams_all_packets_and_audits_the_count()
    {
        var capture = new FakeTrafficCapture(
            TestPackets.Make(TrafficProtocol.Tcp), TestPackets.Make(TrafficProtocol.Udp), TestPackets.Make(TrafficProtocol.Dns));
        var handler = new CaptureTrafficHandler(capture, PassiveGuard(out var audit), audit);

        var received = new List<CapturedPacket>();
        await foreach (var packet in handler.CaptureAsync(new CaptureRequest()))
            received.Add(packet);

        Assert.Equal(3, received.Count);
        var entry = Assert.Single(audit.Entries, e => e.OperationName == "traffic.capture");
        Assert.Equal(AuditOutcome.Completed, entry.Outcome);
        Assert.Contains("3 packet", entry.Detail);
    }

    [Fact]
    public async Task Capture_stops_and_still_audits_when_the_consumer_breaks_early()
    {
        var handler = new CaptureTrafficHandler(new LoopingTrafficCapture(), PassiveGuard(out var audit), audit);
        using var cts = new CancellationTokenSource();

        var received = 0;
        await foreach (var _ in handler.CaptureAsync(new CaptureRequest(), cts.Token))
        {
            if (++received >= 5)
            {
                cts.Cancel();
                break;
            }
        }

        Assert.Equal(5, received);
        Assert.Contains(audit.Entries, e => e.OperationName == "traffic.capture" && e.Outcome == AuditOutcome.Completed);
    }
}
