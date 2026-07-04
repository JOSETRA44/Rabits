using System.Text.Json;

namespace Rabits.Mcp;

/// <summary>A single MCP tool: its name, human description, JSON-Schema for arguments, and the
/// delegate that runs it against the Rabits engine.</summary>
public sealed record ToolDefinition(
    string Name,
    string Description,
    object InputSchema,
    Func<IServiceProvider, JsonElement, CancellationToken, Task<object>> Invoke);
