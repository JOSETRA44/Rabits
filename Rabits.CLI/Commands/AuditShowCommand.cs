using System.ComponentModel;
using Rabits.Application.Abstractions;
using Rabits.CLI.Output;
using Rabits.Domain.Auditing;
using Spectre.Console;
using Spectre.Console.Cli;

namespace Rabits.CLI.Commands;

public sealed class AuditShowSettings : GlobalSettings
{
    [CommandOption("--json")]
    [Description("Emit the audit trail as structured JSON.")]
    public bool Json { get; init; }
}

/// <summary>`rabits audit show` — print the engagement audit trail and verify its hash chain.</summary>
public sealed class AuditShowCommand : AsyncCommand<AuditShowSettings>
{
    private readonly IAuditLog _audit;

    public AuditShowCommand(IAuditLog audit) => _audit = audit;

    public override async Task<int> ExecuteAsync(CommandContext context, AuditShowSettings settings)
    {
        var entries = await _audit.ReadAllAsync();
        var intact = await _audit.VerifyAsync();

        if (settings.Json)
        {
            JsonReport.Emit("audit.show", null, new
            {
                chainIntact = intact,
                count = entries.Count,
                entries = entries.Select(e => new
                {
                    e.Sequence, e.Timestamp, e.Operator, operation = e.OperationName,
                    classification = e.Classification.ToString(), e.Target,
                    outcome = e.Outcome.ToString(), e.Detail, e.Hash,
                }),
            });
            return intact ? 0 : 2;
        }

        if (entries.Count == 0)
        {
            AnsiConsole.MarkupLine("[grey]No audit entries yet.[/]");
            return 0;
        }

        var table = new Table()
            .Border(TableBorder.Rounded)
            .AddColumn(new TableColumn("#").RightAligned())
            .AddColumn("Time")
            .AddColumn("Operation")
            .AddColumn("Class")
            .AddColumn("Target")
            .AddColumn("Outcome");

        foreach (var e in entries)
            table.AddRow(
                e.Sequence.ToString(),
                $"[grey]{e.Timestamp:HH:mm:ss}[/]",
                Markup.Escape(e.OperationName),
                e.Classification.ToString(),
                Markup.Escape(e.Target),
                Outcome(e.Outcome));

        AnsiConsole.Write(table);
        AnsiConsole.MarkupLine(intact
            ? "[green]✓ audit chain intact[/]"
            : "[red]✗ audit chain BROKEN — entries were altered or removed[/]");
        return intact ? 0 : 2;
    }

    private static string Outcome(AuditOutcome outcome) => outcome switch
    {
        AuditOutcome.Authorized => "[green]authorized[/]",
        AuditOutcome.Completed => "[green]completed[/]",
        AuditOutcome.Denied => "[red]denied[/]",
        AuditOutcome.Failed => "[red]failed[/]",
        _ => outcome.ToString(),
    };
}
