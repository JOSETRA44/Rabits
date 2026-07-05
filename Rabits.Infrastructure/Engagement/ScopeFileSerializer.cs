using System.Text.Json;
using System.Text.Json.Serialization;
using Rabits.Domain.Engagement;
using Rabits.Domain.Operations;

namespace Rabits.Infrastructure.Engagement;

/// <summary>Reads and writes the <c>scope.json</c> format shared by the CLI, GUI and MCP server.</summary>
internal static class ScopeFileSerializer
{
    private static readonly JsonSerializerOptions Options = new()
    {
        PropertyNameCaseInsensitive = true,
        WriteIndented = true,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        Converters = { new JsonStringEnumConverter() },
    };

    public static EngagementScope? Read(string path)
    {
        var dto = JsonSerializer.Deserialize<ScopeFileDto>(File.ReadAllText(path), Options);
        if (dto is null || string.IsNullOrWhiteSpace(dto.Name)) return null;

        return new EngagementScope
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
    }

    public static void Write(string path, EngagementScope scope)
    {
        var dto = new ScopeFileDto
        {
            Name = scope.Name,
            StartsAt = scope.StartsAt,
            EndsAt = scope.EndsAt,
            MaxRequestsPerSecond = scope.MaxRequestsPerSecond,
            MaxClassification = scope.MaxClassification,
            Rules = scope.Rules.Select(r => new ScopeRuleDto { Type = r.Type, Pattern = r.Pattern }).ToList(),
        };

        var directory = Path.GetDirectoryName(path);
        if (!string.IsNullOrEmpty(directory)) Directory.CreateDirectory(directory);
        File.WriteAllText(path, JsonSerializer.Serialize(dto, Options));
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
