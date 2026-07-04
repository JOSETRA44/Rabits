using System.Collections.Concurrent;
using System.ComponentModel;
using System.Text.Json;
using Rabits.Application.Traffic;
using Rabits.Domain.Traffic;
using Spectre.Console;
using Spectre.Console.Cli;
using Spectre.Console.Rendering;

namespace Rabits.CLI.Commands;

public sealed class TrafficCaptureSettings : GlobalSettings
{
    [CommandOption("-d|--device <ID>")]
    [Description("Capture device id (default: first).")]
    public string? Device { get; init; }

    [CommandOption("-f|--filter <BPF>")]
    [Description("Berkeley Packet Filter, e.g. \"tcp port 443\".")]
    public string? Filter { get; init; }

    [CommandOption("-n|--count <N>")]
    [Description("Stop after N packets.")]
    public int? Count { get; init; }

    [CommandOption("-s|--seconds <N>")]
    [Description("Stop after N seconds.")]
    public int? Seconds { get; init; }

    [CommandOption("--json")]
    [Description("Emit one JSON object per packet (NDJSON) instead of the live view.")]
    public bool Json { get; init; }
}

/// <summary>`rabits traffic capture` — passive live capture with a real-time rolling view.</summary>
public sealed class TrafficCaptureCommand : AsyncCommand<TrafficCaptureSettings>
{
    private const int RecentWindow = 16;

    private readonly CaptureTrafficHandler _handler;

    public TrafficCaptureCommand(CaptureTrafficHandler handler) => _handler = handler;

    public override async Task<int> ExecuteAsync(CommandContext context, TrafficCaptureSettings settings)
    {
        var request = new CaptureRequest { DeviceId = settings.Device, BpfFilter = settings.Filter };

        using var cts = new CancellationTokenSource();
        if (settings.Seconds is { } seconds) cts.CancelAfter(TimeSpan.FromSeconds(seconds));
        Console.CancelKeyPress += (_, e) => { e.Cancel = true; cts.Cancel(); };

        return settings.Json
            ? await RunNdjsonAsync(request, settings, cts)
            : await RunLiveAsync(request, settings, cts);
    }

    private async Task<int> RunNdjsonAsync(CaptureRequest request, TrafficCaptureSettings settings, CancellationTokenSource cts)
    {
        var captured = 0;
        try
        {
            await foreach (var p in _handler.CaptureAsync(request, cts.Token))
            {
                Console.WriteLine(JsonSerializer.Serialize(new
                {
                    ts = p.Timestamp, protocol = p.Protocol.ToString(), length = p.Length,
                    src = p.SourceEndpoint, dst = p.DestinationEndpoint, info = p.Info,
                }));
                if (settings.Count is { } max && ++captured >= max) break;
            }
        }
        catch (OperationCanceledException) { /* stopped */ }
        return 0;
    }

    private async Task<int> RunLiveAsync(CaptureRequest request, TrafficCaptureSettings settings, CancellationTokenSource cts)
    {
        var aggregator = new TrafficAggregator();
        var recent = new ConcurrentQueue<CapturedPacket>();
        var captured = 0;

        // Background consumer: drains the stream, updates counters + rolling window. Never touches
        // the render loop's state beyond thread-safe structures.
        var consumer = Task.Run(async () =>
        {
            try
            {
                await foreach (var p in _handler.CaptureAsync(request, cts.Token))
                {
                    aggregator.Add(p);
                    recent.Enqueue(p);
                    while (recent.Count > RecentWindow) recent.TryDequeue(out _);
                    if (settings.Count is { } max && Interlocked.Increment(ref captured) >= max)
                    {
                        cts.Cancel();
                        break;
                    }
                }
            }
            catch (OperationCanceledException) { /* stopped */ }
        });

        // The Live view needs an interactive terminal; when redirected/piped, fall back to plain updates.
        if (AnsiConsole.Profile.Capabilities.Interactive)
        {
            await AnsiConsole.Live(Render(aggregator.Snapshot(), Array.Empty<CapturedPacket>()))
                .StartAsync(async ctx =>
                {
                    while (!consumer.IsCompleted)
                    {
                        ctx.UpdateTarget(Render(aggregator.Snapshot(), recent.ToArray()));
                        ctx.Refresh();
                        await Task.Delay(250);
                    }
                    ctx.UpdateTarget(Render(aggregator.Snapshot(), recent.ToArray()));
                    ctx.Refresh();
                });
        }
        else
        {
            while (!consumer.IsCompleted)
            {
                var s = aggregator.Snapshot();
                AnsiConsole.MarkupLine($"[grey]{DateTime.Now:HH:mm:ss}[/] {s.TotalPackets} pkts · {s.PacketsPerSecond:0} pps · {s.TotalBytes:N0} B");
                await Task.Delay(1000);
            }
            AnsiConsole.Write(Render(aggregator.Snapshot(), recent.ToArray()));
        }

        await consumer;
        var stats = aggregator.Snapshot();
        AnsiConsole.MarkupLine($"[grey]Captured {stats.TotalPackets} packet(s), {stats.TotalBytes:N0} bytes.[/]");
        return 0;
    }

    private static IRenderable Render(TrafficStatistics stats, CapturedPacket[] recent)
    {
        var header = $"[bold]{stats.TotalPackets}[/] pkts · [bold]{stats.PacketsPerSecond:0}[/] pps · " +
                     $"{stats.TotalBytes:N0} B    " +
                     $"[green]TCP[/] {stats.CountOf(TrafficProtocol.Tcp)}  " +
                     $"[yellow]UDP[/] {stats.CountOf(TrafficProtocol.Udp)}  " +
                     $"[cyan]DNS[/] {stats.CountOf(TrafficProtocol.Dns)}  " +
                     $"[magenta]ICMP[/] {stats.CountOf(TrafficProtocol.Icmp)}  " +
                     $"[grey]ARP[/] {stats.CountOf(TrafficProtocol.Arp)}";

        var table = new Table().Border(TableBorder.Rounded).Expand().Title(header)
            .AddColumn("Time").AddColumn("Proto").AddColumn("Source").AddColumn("Destination")
            .AddColumn(new TableColumn("Len").RightAligned()).AddColumn("Info");

        foreach (var p in recent.Reverse())
            table.AddRow(
                $"[grey]{p.Timestamp:HH:mm:ss.fff}[/]",
                Protocol(p.Protocol),
                Markup.Escape(p.SourceEndpoint),
                Markup.Escape(p.DestinationEndpoint),
                p.Length.ToString(),
                Markup.Escape(p.Info));

        return table;
    }

    private static string Protocol(TrafficProtocol protocol) => protocol switch
    {
        TrafficProtocol.Tcp => "[green]TCP[/]",
        TrafficProtocol.Udp => "[yellow]UDP[/]",
        TrafficProtocol.Dns => "[cyan]DNS[/]",
        TrafficProtocol.Icmp => "[magenta]ICMP[/]",
        TrafficProtocol.IcmpV6 => "[magenta]ICMPv6[/]",
        TrafficProtocol.Arp => "[grey]ARP[/]",
        _ => "[grey]?[/]",
    };
}
