using System.Text.Json;
using System.Text.Json.Serialization;

namespace Rabits.CLI.Output;

/// <summary>
/// Emits a consistent, self-describing JSON envelope to stdout so external tools and LLM agents can
/// parse and reconstruct any command's findings. Shape: rabits.report/v1
/// { schema, tool, target, generatedAt, operator, scope, data }.
/// </summary>
public static class JsonReport
{
    public static string? Operator { get; set; }
    public static string? Scope { get; set; }

    private static readonly JsonSerializerOptions Options = new()
    {
        WriteIndented = true,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        Converters = { new JsonStringEnumConverter() },
    };

    public static void Emit(string tool, string? target, object data)
    {
        var envelope = new
        {
            schema = "rabits.report/v1",
            tool,
            target,
            generatedAt = DateTimeOffset.Now,
            @operator = Operator,
            scope = Scope,
            data,
        };
        Console.Out.WriteLine(JsonSerializer.Serialize(envelope, Options));
    }

    /// <summary>Serializes an object with the standard options (for callers that build their own output).</summary>
    public static string Serialize(object data) => JsonSerializer.Serialize(data, Options);
}
