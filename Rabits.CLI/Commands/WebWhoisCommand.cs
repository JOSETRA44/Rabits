using System.ComponentModel;
using Rabits.Application.Recon;
using Rabits.CLI.Output;
using Spectre.Console;
using Spectre.Console.Cli;

namespace Rabits.CLI.Commands;

public sealed class WebWhoisSettings : WebDomainSettings
{
    [CommandOption("--raw")]
    [Description("Print the full raw WHOIS response.")]
    public bool Raw { get; init; }
}

/// <summary>`rabits web whois` — passive WHOIS lookup.</summary>
public sealed class WebWhoisCommand : AsyncCommand<WebWhoisSettings>
{
    private readonly WhoisHandler _handler;

    public WebWhoisCommand(WhoisHandler handler) => _handler = handler;

    public override async Task<int> ExecuteAsync(CommandContext context, WebWhoisSettings settings)
    {
        var result = await _handler.HandleAsync(settings.Domain);

        if (settings.Json)
        {
            JsonReport.Emit("web.whois", result.Query, new
            {
                server = result.Server,
                registrar = result.Registrar,
                createdOn = result.CreatedOn,
                expiresOn = result.ExpiresOn,
                daysUntilExpiry = result.DaysUntilExpiry,
                nameServers = result.NameServers,
            });
            return 0;
        }

        var grid = new Grid().AddColumn().AddColumn();
        grid.AddRow("[grey]Domain[/]", Markup.Escape(result.Query));
        grid.AddRow("[grey]WHOIS server[/]", Markup.Escape(result.Server));
        grid.AddRow("[grey]Registrar[/]", Markup.Escape(result.Registrar ?? "—"));
        grid.AddRow("[grey]Created[/]", result.CreatedOn?.ToString("u") ?? "—");
        grid.AddRow("[grey]Expires[/]", FormatExpiry(result.ExpiresOn, result.DaysUntilExpiry));
        grid.AddRow("[grey]Name servers[/]", result.NameServers.Count > 0
            ? Markup.Escape(string.Join("\n", result.NameServers))
            : "—");

        AnsiConsole.Write(new Panel(grid).Header($"WHOIS · {Markup.Escape(result.Query)}").Border(BoxBorder.Rounded));

        if (settings.Raw)
        {
            AnsiConsole.WriteLine();
            AnsiConsole.Write(new Panel(Markup.Escape(result.Raw.Trim())).Header("Raw").Border(BoxBorder.Rounded));
        }

        return 0;
    }

    private static string FormatExpiry(DateTimeOffset? expiry, int? days)
    {
        if (expiry is null) return "—";
        var text = $"{expiry:u}";
        if (days is { } d)
            text += d < 30 ? $" [red]({d} days)[/]" : $" [grey]({d} days)[/]";
        return text;
    }
}
