using System.ComponentModel;
using Rabits.Application.Traffic;
using Rabits.CLI.Output;
using Spectre.Console;
using Spectre.Console.Cli;

namespace Rabits.CLI.Commands;

public sealed class TrafficDevicesSettings : GlobalSettings
{
    [CommandOption("--json")]
    [Description("Emit the device list as structured JSON.")]
    public bool Json { get; init; }
}

/// <summary>`rabits traffic devices` — list interfaces available for capture.</summary>
public sealed class TrafficDevicesCommand : Command<TrafficDevicesSettings>
{
    private readonly CaptureTrafficHandler _handler;

    public TrafficDevicesCommand(CaptureTrafficHandler handler) => _handler = handler;

    public override int Execute(CommandContext context, TrafficDevicesSettings settings)
    {
        var devices = _handler.ListDevices();
        var simulated = devices.Count == 1 && devices[0].Id == "simulated";

        if (settings.Json)
        {
            JsonReport.Emit("traffic.devices", null, new
            {
                backend = simulated ? "simulated" : "npcap",
                devices = devices.Select(d => new { d.Id, d.Name, d.Description }),
            });
            return 0;
        }

        AnsiConsole.MarkupLine(simulated
            ? "[yellow]No Npcap backend — using the simulated interface.[/]"
            : "[green]Real capture backend available (Npcap).[/]");

        if (devices.Count == 0)
        {
            AnsiConsole.MarkupLine("[grey]No capture devices found.[/]");
            return 0;
        }

        var table = new Table().Border(TableBorder.Rounded)
            .AddColumn(new TableColumn("#").RightAligned())
            .AddColumn("Id")
            .AddColumn("Description");

        for (var i = 0; i < devices.Count; i++)
            table.AddRow(i.ToString(), $"[grey]{Markup.Escape(devices[i].Id)}[/]", Markup.Escape(devices[i].Description));

        AnsiConsole.Write(table);
        return 0;
    }
}
