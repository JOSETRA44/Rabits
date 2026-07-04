using System.ComponentModel;
using System.Text.Json;
using Rabits.Application.Hosts;
using Rabits.Domain.Engagement;
using Rabits.Domain.Networking;
using Spectre.Console;
using Spectre.Console.Cli;

namespace Rabits.CLI.Commands;

public sealed class HostsDiscoverSettings : GlobalSettings
{
    [CommandArgument(0, "<TARGET>")]
    [Description("Target as CIDR (10.0.0.0/24) or a single IP.")]
    public string Target { get; init; } = string.Empty;

    [CommandOption("-p|--ports <PROFILE>")]
    [Description("Port scan profile: none | common | top100 | artillery.")]
    [DefaultValue("none")]
    public string Ports { get; init; } = "none";

    [CommandOption("-c|--concurrency <N>")]
    [Description("Simultaneous host probes.")]
    [DefaultValue(64)]
    public int Concurrency { get; init; } = 64;

    [CommandOption("--no-mac")]
    [Description("Skip ARP/MAC and vendor resolution.")]
    public bool NoMac { get; init; }

    [CommandOption("--hostname")]
    [Description("Resolve reverse DNS (PTR) for each host.")]
    public bool ResolveHostname { get; init; }

    [CommandOption("--json")]
    [Description("Emit results as JSON.")]
    public bool Json { get; init; }
}

/// <summary>`rabits hosts discover` — active host discovery + optional port scan (scope-gated).</summary>
public sealed class HostsDiscoverCommand : AsyncCommand<HostsDiscoverSettings>
{
    private readonly DiscoverHostsHandler _handler;

    public HostsDiscoverCommand(DiscoverHostsHandler handler) => _handler = handler;

    public override async Task<int> ExecuteAsync(CommandContext context, HostsDiscoverSettings settings)
    {
        if (!TryParseProfile(settings.Ports, out var profile))
        {
            AnsiConsole.MarkupLineInterpolated($"[red]Unknown port profile '{settings.Ports}'.[/] Use none|common|top100|artillery.");
            return 1;
        }

        var request = new HostDiscoveryRequest
        {
            Target = settings.Target,
            Ports = profile,
            Concurrency = settings.Concurrency,
            ResolveMac = !settings.NoMac,
            ResolveHostname = settings.ResolveHostname,
        };

        using var cts = new CancellationTokenSource();
        Console.CancelKeyPress += (_, e) => { e.Cancel = true; cts.Cancel(); };

        try
        {
            IReadOnlyList<DiscoveredHost> hosts = Array.Empty<DiscoveredHost>();
            var found = 0;
            var progress = new Progress<DiscoveredHost>(_ => Interlocked.Increment(ref found));

            await AnsiConsole.Status().Spinner(Spinner.Known.Dots).StartAsync(
                $"Discovering hosts in [bold]{Markup.Escape(settings.Target)}[/]…",
                async ctx =>
                {
                    var task = _handler.HandleAsync(request, progress, cts.Token);
                    while (!task.IsCompleted)
                    {
                        ctx.Status($"Discovering [bold]{Markup.Escape(settings.Target)}[/] — {found} host(s) up…");
                        await Task.WhenAny(task, Task.Delay(200, cts.Token));
                    }
                    hosts = await task;
                });

            if (settings.Json)
                EmitJson(hosts);
            else
                Render(hosts, settings.Target, profile);

            return 0;
        }
        catch (OutOfScopeException ex)
        {
            AnsiConsole.MarkupLineInterpolated($"[red]Refused — out of scope:[/] {ex.Message}");
            AnsiConsole.MarkupLine("[grey]Load an engagement scope that covers this range (see scope.example.json).[/]");
            return 3;
        }
        catch (ArgumentException ex)
        {
            AnsiConsole.MarkupLineInterpolated($"[red]{ex.Message}[/]");
            return 1;
        }
        catch (OperationCanceledException)
        {
            return 0;
        }
    }

    private static void Render(IReadOnlyList<DiscoveredHost> hosts, string target, PortScanProfile profile)
    {
        var table = new Table()
            .Border(TableBorder.Rounded)
            .Title($"[bold]{hosts.Count}[/] host(s) up in {Markup.Escape(target)}")
            .AddColumn("IP")
            .AddColumn("Status")
            .AddColumn("MAC")
            .AddColumn("Vendor")
            .AddColumn(new TableColumn("Latency").RightAligned());

        if (profile != PortScanProfile.None)
            table.AddColumn("Open ports");

        foreach (var h in hosts)
        {
            var latency = h.Latency is { } l ? $"{l.TotalMilliseconds:0} ms" : "[grey]—[/]";
            var row = new List<string>
            {
                $"[bold]{h.Address}[/]",
                $"[green]● up[/] [grey]({h.Method})[/]",
                h.Mac is { } mac ? $"[grey]{mac}[/]" : "[grey]—[/]",
                h.Vendor is { } v ? Markup.Escape(v) : "[grey]unknown[/]",
                latency,
            };
            if (profile != PortScanProfile.None)
            {
                var ports = h.OpenPorts.Count > 0
                    ? string.Join(", ", h.OpenPorts.Select(p => Markup.Escape(p.ToString())))
                    : "[grey]none[/]";
                row.Add(ports);
            }
            table.AddRow(row.ToArray());
        }

        AnsiConsole.Write(table);
    }

    private static void EmitJson(IReadOnlyList<DiscoveredHost> hosts)
    {
        var projection = hosts.Select(h => new
        {
            ip = h.Address.ToString(),
            status = h.Status.ToString(),
            method = h.Method.ToString(),
            mac = h.Mac?.ToString(),
            vendor = h.Vendor,
            hostname = h.Hostname,
            latencyMs = h.Latency?.TotalMilliseconds,
            openPorts = h.OpenPorts.Select(p => new { p.Number, service = p.Service }),
        });

        Console.WriteLine(JsonSerializer.Serialize(projection, new JsonSerializerOptions { WriteIndented = true }));
    }

    private static bool TryParseProfile(string value, out PortScanProfile profile)
    {
        switch (value.Trim().ToLowerInvariant())
        {
            case "none": profile = PortScanProfile.None; return true;
            case "common": profile = PortScanProfile.Common; return true;
            case "top100": profile = PortScanProfile.Top100; return true;
            case "artillery": profile = PortScanProfile.Artillery; return true;
            default: profile = PortScanProfile.None; return false;
        }
    }
}
