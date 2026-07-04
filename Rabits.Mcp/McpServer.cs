using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.Extensions.Logging;

namespace Rabits.Mcp;

/// <summary>
/// A minimal, dependency-free Model Context Protocol server over stdio. Speaks newline-delimited
/// JSON-RPC 2.0 on stdin/stdout (diagnostics go to stderr) and dispatches tool calls to the Rabits
/// engine. Implements initialize, tools/list, tools/call and ping.
/// </summary>
public sealed class McpServer
{
    private const string ProtocolVersion = "2024-11-05";

    private static readonly JsonSerializerOptions Compact = new()
    {
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        Converters = { new JsonStringEnumConverter() },
    };
    private static readonly JsonSerializerOptions Pretty = new()
    {
        WriteIndented = true,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        Converters = { new JsonStringEnumConverter() },
    };

    private readonly IServiceProvider _services;
    private readonly IReadOnlyList<ToolDefinition> _tools;
    private readonly ILogger<McpServer> _logger;

    public McpServer(IServiceProvider services, IReadOnlyList<ToolDefinition> tools, ILogger<McpServer> logger)
    {
        _services = services;
        _tools = tools;
        _logger = logger;
    }

    public async Task RunAsync(CancellationToken cancellationToken)
    {
        using var reader = new StreamReader(Console.OpenStandardInput(), Encoding.UTF8);
        await using var writer = new StreamWriter(Console.OpenStandardOutput(), new UTF8Encoding(false))
        {
            NewLine = "\n",
            AutoFlush = true,
        };

        _logger.LogInformation("Rabits MCP server ready ({Count} tools).", _tools.Count);

        while (!cancellationToken.IsCancellationRequested)
        {
            var line = await reader.ReadLineAsync(cancellationToken);
            if (line is null) break;                 // stdin closed
            if (line.Length == 0) continue;

            string? response;
            try
            {
                response = await HandleAsync(line, cancellationToken);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Unhandled error processing message.");
                response = null;
            }

            if (response is not null)
                await writer.WriteLineAsync(response);
        }
    }

    private async Task<string?> HandleAsync(string line, CancellationToken cancellationToken)
    {
        using var doc = JsonDocument.Parse(line);
        var root = doc.RootElement;
        var method = root.TryGetProperty("method", out var m) ? m.GetString() : null;
        var hasId = root.TryGetProperty("id", out var idElement);
        var id = hasId ? idElement.Clone() : default;

        switch (method)
        {
            case "initialize":
                return Result(id, new
                {
                    protocolVersion = ProtocolVersion,
                    capabilities = new { tools = new { } },
                    serverInfo = new { name = "rabits-mcp", version = "1.0.0" },
                });

            case "notifications/initialized":
            case "notifications/cancelled":
                return null; // notifications get no response

            case "ping":
                return Result(id, new { });

            case "tools/list":
                return Result(id, new
                {
                    tools = _tools.Select(t => new { name = t.Name, description = t.Description, inputSchema = t.InputSchema }),
                });

            case "tools/call":
                return await CallToolAsync(id, root, cancellationToken);

            default:
                return hasId ? Error(id, -32601, $"Method not found: {method}") : null;
        }
    }

    private async Task<string?> CallToolAsync(JsonElement id, JsonElement root, CancellationToken cancellationToken)
    {
        if (!root.TryGetProperty("params", out var prms) || !prms.TryGetProperty("name", out var nameEl))
            return Error(id, -32602, "Missing tool name.");

        var name = nameEl.GetString();
        var tool = _tools.FirstOrDefault(t => t.Name == name);
        if (tool is null)
            return Error(id, -32602, $"Unknown tool: {name}");

        var arguments = prms.TryGetProperty("arguments", out var a) ? a : default;

        try
        {
            var result = await tool.Invoke(_services, arguments, cancellationToken);
            var text = JsonSerializer.Serialize(result, Pretty);
            return Result(id, new
            {
                content = new[] { new { type = "text", text } },
                isError = false,
            });
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Tool {Tool} failed.", name);
            return Result(id, new
            {
                content = new[] { new { type = "text", text = $"Error: {ex.Message}" } },
                isError = true,
            });
        }
    }

    private static string Result(JsonElement id, object result)
        => JsonSerializer.Serialize(new JsonRpcResponse { Id = id, Result = result }, Compact);

    private static string Error(JsonElement id, int code, string message)
        => JsonSerializer.Serialize(new JsonRpcResponse { Id = id, Error = new { code, message } }, Compact);

    private sealed class JsonRpcResponse
    {
        [JsonPropertyName("jsonrpc")] public string JsonRpc => "2.0";
        [JsonPropertyName("id")] public JsonElement Id { get; init; }
        [JsonPropertyName("result")] public object? Result { get; init; }
        [JsonPropertyName("error")] public object? Error { get; init; }
    }
}
