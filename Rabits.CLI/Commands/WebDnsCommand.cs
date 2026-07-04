using System.ComponentModel;
using Rabits.Application.Recon;
using Rabits.CLI.Output;
using Spectre.Console;
using Spectre.Console.Cli;

namespace Rabits.CLI.Commands;

public class WebDomainSettings : GlobalSettings
{
    [CommandArgument(0, "<DOMAIN>")]
    [Description("Domain name to look up.")]
    public string Domain { get; init; } = string.Empty;

    [CommandOption("--json")]
    public bool Json { get; init; }
}

/// <summary>`rabits web dns` — passive DNS record enumeration.</summary>
public sealed class WebDnsCommand : AsyncCommand<WebDomainSettings>
{
    private readonly DnsReconHandler _handler;

    public WebDnsCommand(DnsReconHandler handler) => _handler = handler;

    public override async Task<int> ExecuteAsync(CommandContext context, WebDomainSettings settings)
    {
        var records = await _handler.HandleAsync(settings.Domain);

        if (settings.Json)
        {
            JsonReport.Emit("web.dns", settings.Domain,
                records.Select(r => new { type = r.Type.ToString(), value = r.Value, ttl = r.Ttl }));
            return 0;
        }

        if (records.Count == 0)
        {
            AnsiConsole.MarkupLineInterpolated($"[grey]No DNS records for {settings.Domain}.[/]");
            return 0;
        }

        var table = new Table().Border(TableBorder.Rounded)
            .Title($"DNS · [bold]{Markup.Escape(settings.Domain)}[/]")
            .AddColumn("Type").AddColumn("Value").AddColumn(new TableColumn("TTL").RightAligned());

        foreach (var r in records.OrderBy(r => r.Type))
            table.AddRow($"[cyan]{r.Type}[/]", Markup.Escape(r.Value), $"[grey]{r.Ttl}[/]");

        AnsiConsole.Write(table);
        return 0;
    }
}
