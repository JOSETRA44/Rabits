using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Rabits.Infrastructure.DependencyInjection;
using Rabits.Mcp;

// Configuration via environment variables (an MCP client sets these in its server config).
static string? Env(string name) => Environment.GetEnvironmentVariable(name);

var services = new ServiceCollection();

// All diagnostics go to stderr; stdout is reserved for the JSON-RPC protocol stream.
services.AddLogging(builder => builder
    .AddSimpleConsole(o => o.SingleLine = true)
    .SetMinimumLevel(LogLevel.Warning));
services.Configure<Microsoft.Extensions.Logging.Console.ConsoleLoggerOptions>(
    o => o.LogToStandardErrorThreshold = LogLevel.Trace);

services.AddRabitsEngine(options =>
{
    if (Env("RABITS_SCOPE") is { Length: > 0 } scope) options.ScopeFilePath = scope;
    if (Env("RABITS_AUDIT") is { Length: > 0 } audit) options.AuditLogPath = audit;
    if (Env("RABITS_SIMULATE") == "1") options.ForceSimulatedCapture = true;
    if (Env("RABITS_GOD_MODE") == "1") options.BypassScope = true;
});

services.AddSingleton<McpServer>();
services.AddSingleton<IReadOnlyList<ToolDefinition>>(RabitsToolset.Build());

await using var provider = services.BuildServiceProvider();

using var cts = new CancellationTokenSource();
Console.CancelKeyPress += (_, e) => { e.Cancel = true; cts.Cancel(); };

await provider.GetRequiredService<McpServer>().RunAsync(cts.Token);
