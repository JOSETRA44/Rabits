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
    options.ForceSimulatedCapture = globals.Simulate;
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
    config.AddBranch("hosts", hosts =>
    {
        hosts.SetDescription("Host discovery and network mapping.");
        hosts.AddCommand<HostsDiscoverCommand>("discover")
            .WithDescription("Active host sweep (ICMP + ARP) with optional port scan.");
    });
    config.AddBranch("web", web =>
    {
        web.SetDescription("Web and domain reconnaissance.");
        web.AddCommand<WebDnsCommand>("dns").WithDescription("Passive DNS record enumeration.");
        web.AddCommand<WebWhoisCommand>("whois").WithDescription("Passive WHOIS lookup.");
        web.AddCommand<WebSubdomainsCommand>("subdomains").WithDescription("Passive subdomain enumeration.");
        web.AddCommand<WebHeadersCommand>("headers").WithDescription("Active HTTP/TLS + security-header audit.");
    });
    config.AddBranch("traffic", traffic =>
    {
        traffic.SetDescription("Live traffic capture and analysis.");
        traffic.AddCommand<TrafficDevicesCommand>("devices").WithDescription("List capture interfaces.");
        traffic.AddCommand<TrafficCaptureCommand>("capture").WithDescription("Live capture with real-time stats.");
    });
    config.AddBranch("audit", audit =>
    {
        audit.SetDescription("Engagement audit trail.");
        audit.AddCommand<AuditShowCommand>("show").WithDescription("Print the trail and verify its chain.");
    });
});

return await app.RunAsync(args);

static (string? ScopePath, string? AuditPath, bool Fake, bool Simulate) PreScan(string[] args)
{
    string? scope = null, audit = null;
    var fake = false;
    var simulate = false;
    for (var i = 0; i < args.Length; i++)
    {
        switch (args[i])
        {
            case "--fake":
                fake = true;
                break;
            case "--simulate":
                simulate = true;
                break;
            case "--scope" when i + 1 < args.Length:
                scope = args[++i];
                break;
            case "--audit" when i + 1 < args.Length:
                audit = args[++i];
                break;
        }
    }
    return (scope, audit, fake, simulate);
}
