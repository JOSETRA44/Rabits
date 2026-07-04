using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.Extensions.Logging;
using Rabits.Application.Abstractions;
using Rabits.Domain.Engagement;
using Rabits.Domain.Operations;

namespace Rabits.Infrastructure.Engagement;

/// <summary>
/// Loads an <see cref="EngagementScope"/> from a JSON file once at startup. When the file is
/// missing or invalid, <see cref="Current"/> is null and the gate denies all active operations.
/// </summary>
public sealed class JsonScopePolicy : IScopePolicy
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNameCaseInsensitive = true,
        Converters = { new JsonStringEnumConverter() },
    };

    public EngagementScope? Current { get; }

    public JsonScopePolicy(string scopeFilePath, ILogger<JsonScopePolicy> logger)
    {
        if (!File.Exists(scopeFilePath))
        {
            logger.LogWarning("No engagement scope at '{Path}'. Active operations are disabled.", scopeFilePath);
            return;
        }

        try
        {
            var dto = JsonSerializer.Deserialize<ScopeFileDto>(File.ReadAllText(scopeFilePath), JsonOptions);
            if (dto is null || string.IsNullOrWhiteSpace(dto.Name))
            {
                logger.LogError("Engagement scope at '{Path}' is empty or missing a name.", scopeFilePath);
                return;
            }

            Current = new EngagementScope
            {
                Name = dto.Name,
                StartsAt = dto.StartsAt,
                EndsAt = dto.EndsAt,
                MaxRequestsPerSecond = dto.MaxRequestsPerSecond,
                MaxClassification = dto.MaxClassification,
                Rules = (dto.Rules ?? new List<ScopeRuleDto>())
                    .Select(r => new ScopeRule(r.Type, r.Pattern))
                    .ToList(),
            };

            logger.LogInformation("Loaded engagement scope '{Name}' with {Count} rule(s).",
                Current.Name, Current.Rules.Count);
        }
        catch (JsonException ex)
        {
            logger.LogError(ex, "Failed to parse engagement scope at '{Path}'.", scopeFilePath);
        }
    }

    private sealed class ScopeFileDto
    {
        public string Name { get; set; } = string.Empty;
        public DateTimeOffset? StartsAt { get; set; }
        public DateTimeOffset? EndsAt { get; set; }
        public int? MaxRequestsPerSecond { get; set; }
        public OperationClassification MaxClassification { get; set; } = OperationClassification.Active;
        public List<ScopeRuleDto>? Rules { get; set; }
    }

    private sealed class ScopeRuleDto
    {
        public TargetType Type { get; set; }
        public string Pattern { get; set; } = string.Empty;
    }
}
