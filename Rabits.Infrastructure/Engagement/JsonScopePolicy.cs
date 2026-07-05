using Microsoft.Extensions.Logging;
using Rabits.Application.Abstractions;
using Rabits.Domain.Engagement;
using Rabits.Domain.Operations;

namespace Rabits.Infrastructure.Engagement;

/// <summary>
/// File-backed engagement scope that stays live during a session. It hot-reloads on external edits
/// (checks the file's last-write time on every access) and supports in-session authorization that is
/// persisted back to disk. Because the authorization gate reads <see cref="Current"/> on every
/// operation, an <see cref="Authorize"/> call takes effect immediately — no process restart.
/// </summary>
public sealed class JsonScopePolicy : IScopePolicy
{
    private readonly string _path;
    private readonly ILogger<JsonScopePolicy> _logger;
    private readonly object _lock = new();

    private EngagementScope? _current;
    private DateTime _loadedWriteTimeUtc = DateTime.MinValue;

    public JsonScopePolicy(string scopeFilePath, ILogger<JsonScopePolicy> logger)
    {
        _path = scopeFilePath;
        _logger = logger;
        lock (_lock) ReloadIfChanged(force: true);
    }

    public EngagementScope? Current
    {
        get { lock (_lock) { ReloadIfChanged(); return _current; } }
    }

    public EngagementScope Authorize(ScopeRule rule, OperationClassification? raiseTo = null)
    {
        lock (_lock)
        {
            ReloadIfChanged();

            var scope = _current ?? new EngagementScope
            {
                Name = "Ad-hoc session",
                MaxClassification = OperationClassification.Active,
            };

            scope = scope.WithRule(rule);
            if (raiseTo is { } classification && classification > scope.MaxClassification)
                scope = scope.WithMaxClassification(classification);

            _current = scope;
            Persist();
            _logger.LogInformation("Authorized {Type} '{Pattern}' (scope now {Count} rule(s), max {Max}).",
                rule.Type, rule.Pattern, scope.Rules.Count, scope.MaxClassification);
            return scope;
        }
    }

    public bool Revoke(string pattern)
    {
        lock (_lock)
        {
            ReloadIfChanged();
            if (_current is null) return false;

            var updated = _current.WithoutRule(pattern);
            if (updated.Rules.Count == _current.Rules.Count) return false;

            _current = updated;
            Persist();
            return true;
        }
    }

    public void Reload()
    {
        lock (_lock) ReloadIfChanged(force: true);
    }

    private void ReloadIfChanged(bool force = false)
    {
        try
        {
            if (!File.Exists(_path))
            {
                if (force && _current is null)
                    _logger.LogWarning("No engagement scope at '{Path}'. Active operations are disabled until authorized.", _path);
                return;
            }

            var writeTime = File.GetLastWriteTimeUtc(_path);
            if (!force && writeTime == _loadedWriteTimeUtc) return;

            _current = ScopeFileSerializer.Read(_path);
            _loadedWriteTimeUtc = writeTime;
            if (_current is not null)
                _logger.LogInformation("Loaded engagement scope '{Name}' ({Count} rule(s)).", _current.Name, _current.Rules.Count);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to load engagement scope at '{Path}'.", _path);
        }
    }

    private void Persist()
    {
        try
        {
            ScopeFileSerializer.Write(_path, _current!);
            _loadedWriteTimeUtc = File.GetLastWriteTimeUtc(_path); // avoid reloading our own write
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to persist engagement scope to '{Path}'.", _path);
        }
    }
}
