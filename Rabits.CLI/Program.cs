using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Rabits.CLI.Commands;
using Rabits.CLI.Infrastructure;
using Rabits.Infrastructure;
using Rabits.Infrastructure.DependencyInjection;
using Spectre.Console.Cli;

// Global options are pre-scanned so the engine can be configured before the DI container is built.
var globals = PreScan(args);

var services = new ServiceCollection();
services.AddLogging(builder => builder
    .AddSimpleConsole(o => o.SingleLine = true)
    .SetMinimumLevel(LogLevel.Warning));

services.AddRabitsEngine(options =>
{
    if (globals.ScopePath is not null) options.ScopeFilePath = globals.ScopePath;
    if (globals.AuditPath is not null) options.AuditLogPath = globals.AuditPath;
    options.ForceFakeScanner = globals.Fake;
});

var app = new CommandApp(new TypeRegistrar(services));
app.Configure(config =>
{
    config.SetApplicationName("rabits");
    config.AddBranch("wifi", wifi =>
    {
        wifi.SetDescription("Wireless reconnaissance.");
        wifi.AddCommand<WifiScanCommand>("scan").WithDescription("Passively scan for nearby networks.");
    });
    config.AddBranch("audit", audit =>
    {
        audit.SetDescription("Engagement audit trail.");
        audit.AddCommand<AuditShowCommand>("show").WithDescription("Print the trail and verify its chain.");
    });
});

return await app.RunAsync(args);

static (string? ScopePath, string? AuditPath, bool Fake) PreScan(string[] args)
{
    string? scope = null, audit = null;
    var fake = false;
    for (var i = 0; i < args.Length; i++)
    {
        switch (args[i])
        {
            case "--fake":
                fake = true;
                break;
            case "--scope" when i + 1 < args.Length:
                scope = args[++i];
                break;
            case "--audit" when i + 1 < args.Length:
                audit = args[++i];
                break;
        }
    }
    return (scope, audit, fake);
}
