using System.ComponentModel;
using System.Text.Json;
using Rabits.Application.Wireless;
using Rabits.CLI.Rendering;
using Rabits.Domain.Networking;
using Spectre.Console;
using Spectre.Console.Cli;

namespace Rabits.CLI.Commands;

public sealed class WifiScanSettings : GlobalSettings
{
    [CommandOption("--json")]
    [Description("Emit results as JSON instead of a table.")]
    public bool Json { get; init; }

    [CommandOption("-w|--watch")]
    [Description("Continuously re-scan until Ctrl+C.")]
    public bool Watch { get; init; }

    [CommandOption("-i|--interval <SECONDS>")]
    [Description("Seconds between scans in --watch mode.")]
    [DefaultValue(5)]
    public int IntervalSeconds { get; init; } = 5;
}

/// <summary>`rabits wifi scan` — passive enumeration of nearby wireless networks.</summary>
public sealed class WifiScanCommand : AsyncCommand<WifiScanSettings>
{
    private readonly ScanWirelessNetworksHandler _handler;

    public WifiScanCommand(ScanWirelessNetworksHandler handler) => _handler = handler;

    public override async Task<int> ExecuteAsync(CommandContext context, WifiScanSettings settings)
    {
        using var cts = new CancellationTokenSource();
        Console.CancelKeyPress += (_, e) => { e.Cancel = true; cts.Cancel(); };

        try
        {
            if (settings.Watch && !settings.Json)
            {
                await WatchAsync(settings, cts.Token);
                return 0;
            }

            var networks = await ScanAsync(cts.Token);
            if (settings.Json)
                EmitJson(networks);
            else
                AnsiConsole.Write(BuildTable(networks));

            return 0;
        }
        catch (OperationCanceledException)
        {
            return 0;
        }
        catch (Exception ex)
        {
            AnsiConsole.MarkupLineInterpolated($"[red]Scan failed:[/] {ex.Message}");
            return 1;
        }
    }

    private async Task<IReadOnlyList<WirelessNetwork>> ScanAsync(CancellationToken token)
    {
        IReadOnlyList<WirelessNetwork> networks = Array.Empty<WirelessNetwork>();
        await AnsiConsole.Status()
            .Spinner(Spinner.Known.Dots)
            .StartAsync("Scanning for wireless networks…", async _ => networks = await _handler.HandleAsync(token));
        return networks;
    }

    private async Task WatchAsync(WifiScanSettings settings, CancellationToken token)
    {
        while (!token.IsCancellationRequested)
        {
            var networks = await ScanAsync(token);
            AnsiConsole.Clear();
            AnsiConsole.MarkupLineInterpolated($"[grey]Rabits · Wi-Fi · {DateTime.Now:HH:mm:ss} · Ctrl+C to stop[/]");
            AnsiConsole.Write(BuildTable(networks));
            await Task.Delay(TimeSpan.FromSeconds(Math.Max(1, settings.IntervalSeconds)), token);
        }
    }

    private static Table BuildTable(IReadOnlyList<WirelessNetwork> networks)
    {
        var table = new Table()
            .Border(TableBorder.Rounded)
            .Title($"[bold]{networks.Count}[/] wireless network(s)")
            .AddColumn("SSID")
            .AddColumn("BSSID")
            .AddColumn("Signal")
            .AddColumn(new TableColumn("Ch").RightAligned())
            .AddColumn("Band")
            .AddColumn("Encryption");

        foreach (var n in networks)
        {
            table.AddRow(
                Markup.Escape(n.DisplaySsid),
                $"[grey]{n.Bssid}[/]",
                NetworkFormatting.Signal(n.Rssi),
                n.Channel.Number > 0 ? n.Channel.Number.ToString() : "-",
                NetworkFormatting.Band(n.Channel.Band),
                NetworkFormatting.Encryption(n.Encryption));
        }

        return table;
    }

    private static void EmitJson(IReadOnlyList<WirelessNetwork> networks)
    {
        var projection = networks.Select(n => new
        {
            ssid = n.Ssid,
            hidden = n.IsHidden,
            bssid = n.Bssid.ToString(),
            oui = n.Bssid.Oui,
            rssiDbm = n.Rssi.Dbm,
            quality = n.Rssi.QualityPercent,
            channel = n.Channel.Number,
            band = n.Channel.Band.ToString(),
            encryption = n.Encryption.ToString(),
            open = n.IsOpen,
        });

        Console.WriteLine(JsonSerializer.Serialize(projection, new JsonSerializerOptions { WriteIndented = true }));
    }
}
