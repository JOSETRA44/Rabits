using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Rabits.Application.Abstractions;
using Rabits.Domain.Auditing;
using Rabits.Domain.Operations;

namespace Rabits.Infrastructure.Auditing;

/// <summary>
/// Append-only, hash-chained audit trail persisted as JSON Lines. Sequencing and the previous-hash
/// link are managed here; on first use the tail of the existing file is read to continue the chain.
/// </summary>
public sealed class FileAuditLog : IAuditLog
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        Converters = { new JsonStringEnumConverter() },
        WriteIndented = false,
    };

    private readonly string _path;
    private readonly IClock _clock;
    private readonly SemaphoreSlim _mutex = new(1, 1);

    private bool _initialized;
    private long _lastSequence;
    private string _lastHash = AuditEntry.GenesisHash;

    public FileAuditLog(string path, IClock clock)
    {
        _path = path;
        _clock = clock;
    }

    public async Task<AuditEntry> RecordAsync(
        RabitsOperation operation, AuditOutcome outcome, string detail, CancellationToken cancellationToken = default)
    {
        await _mutex.WaitAsync(cancellationToken);
        try
        {
            await EnsureInitializedAsync(cancellationToken);

            var entry = AuditEntry.Create(
                _lastSequence + 1, _clock.Now, "engine", operation, outcome, detail, _lastHash);

            var directory = Path.GetDirectoryName(_path);
            if (!string.IsNullOrEmpty(directory))
                Directory.CreateDirectory(directory);

            var line = JsonSerializer.Serialize(entry, JsonOptions) + Environment.NewLine;
            await File.AppendAllTextAsync(_path, line, Encoding.UTF8, cancellationToken);

            _lastSequence = entry.Sequence;
            _lastHash = entry.Hash;
            return entry;
        }
        finally
        {
            _mutex.Release();
        }
    }

    public async Task<IReadOnlyList<AuditEntry>> ReadAllAsync(CancellationToken cancellationToken = default)
    {
        if (!File.Exists(_path)) return Array.Empty<AuditEntry>();

        var entries = new List<AuditEntry>();
        foreach (var line in await File.ReadAllLinesAsync(_path, cancellationToken))
        {
            if (string.IsNullOrWhiteSpace(line)) continue;
            var entry = JsonSerializer.Deserialize<AuditEntry>(line, JsonOptions);
            if (entry is not null) entries.Add(entry);
        }
        return entries;
    }

    public async Task<bool> VerifyAsync(CancellationToken cancellationToken = default)
    {
        var entries = await ReadAllAsync(cancellationToken);
        var previous = AuditEntry.GenesisHash;
        var expectedSequence = 1L;

        foreach (var entry in entries)
        {
            if (entry.Sequence != expectedSequence || entry.PreviousHash != previous)
                return false;

            var recomputed = AuditEntry.Create(
                entry.Sequence, entry.Timestamp, entry.Operator,
                new RabitsOperation(entry.OperationName, entry.Classification, entry.Target),
                entry.Outcome, entry.Detail, entry.PreviousHash);

            if (recomputed.Hash != entry.Hash) return false;

            previous = entry.Hash;
            expectedSequence++;
        }

        return true;
    }

    private async Task EnsureInitializedAsync(CancellationToken cancellationToken)
    {
        if (_initialized) return;

        if (File.Exists(_path))
        {
            var lines = await File.ReadAllLinesAsync(_path, cancellationToken);
            for (var i = lines.Length - 1; i >= 0; i--)
            {
                if (string.IsNullOrWhiteSpace(lines[i])) continue;
                var last = JsonSerializer.Deserialize<AuditEntry>(lines[i], JsonOptions);
                if (last is not null)
                {
                    _lastSequence = last.Sequence;
                    _lastHash = last.Hash;
                }
                break;
            }
        }

        _initialized = true;
    }
}
