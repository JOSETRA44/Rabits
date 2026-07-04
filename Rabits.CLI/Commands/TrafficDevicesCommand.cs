using Rabits.Application.Traffic;
using Spectre.Console;
using Spectre.Console.Cli;

namespace Rabits.CLI.Commands;

/// <summary>`rabits traffic devices` — list interfaces available for capture.</summary>
public sealed class TrafficDevicesCommand : Command<GlobalSettings>
{
    private readonly CaptureTrafficHandler _handler;

    public TrafficDevicesCommand(CaptureTrafficHandler handler) => _handler = handler;

    public override int Execute(CommandContext context, GlobalSettings settings)
    {
        var devices = _handler.ListDevices();
        var simulated = devices.Count == 1 && devices[0].Id == "simulated";
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
