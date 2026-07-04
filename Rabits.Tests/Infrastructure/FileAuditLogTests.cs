using Rabits.Domain.Auditing;
using Rabits.Domain.Operations;
using Rabits.Infrastructure.Auditing;

namespace Rabits.Tests.Infrastructure;

public class FileAuditLogTests : IDisposable
{
    private readonly string _path = Path.Combine(Path.GetTempPath(), $"rabits-audit-{Guid.NewGuid():N}.jsonl");
    private readonly FixedClock _clock = new(new DateTimeOffset(2026, 7, 3, 9, 0, 0, TimeSpan.Zero));

    [Fact]
    public async Task Records_and_verifies_an_intact_chain()
    {
        var log = new FileAuditLog(_path, _clock);
        await log.RecordAsync(RabitsOperation.Passive("wifi.scan"), AuditOutcome.Completed, "8 networks");
        await log.RecordAsync(RabitsOperation.Active("port.scan", "10.0.0.5"), AuditOutcome.Authorized, "in scope");

        var entries = await log.ReadAllAsync();
        Assert.Equal(2, entries.Count);
        Assert.Equal(1, entries[0].Sequence);
        Assert.Equal(AuditEntry.GenesisHash, entries[0].PreviousHash);
        Assert.Equal(entries[0].Hash, entries[1].PreviousHash);
        Assert.True(await log.VerifyAsync());
    }

    [Fact]
    public async Task Continues_the_chain_across_instances()
    {
        var first = new FileAuditLog(_path, _clock);
        await first.RecordAsync(RabitsOperation.Passive("wifi.scan"), AuditOutcome.Completed, "first");

        var second = new FileAuditLog(_path, _clock);
        await second.RecordAsync(RabitsOperation.Passive("wifi.scan"), AuditOutcome.Completed, "second");

        var entries = await second.ReadAllAsync();
        Assert.Equal(new long[] { 1, 2 }, entries.Select(e => e.Sequence));
        Assert.True(await second.VerifyAsync());
    }

    [Fact]
    public async Task Detects_a_tampered_entry()
    {
        var log = new FileAuditLog(_path, _clock);
        await log.RecordAsync(RabitsOperation.Passive("wifi.scan"), AuditOutcome.Completed, "original");
        await log.RecordAsync(RabitsOperation.Passive("wifi.scan"), AuditOutcome.Completed, "second");

        var text = await File.ReadAllTextAsync(_path);
        await File.WriteAllTextAsync(_path, text.Replace("original", "TAMPERED"));

        Assert.False(await new FileAuditLog(_path, _clock).VerifyAsync());
    }

    public void Dispose()
    {
        if (File.Exists(_path)) File.Delete(_path);
    }
}
