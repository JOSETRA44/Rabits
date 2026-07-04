using System.ComponentModel;
using Rabits.Application.Recon;
using Rabits.CLI.Output;
using Rabits.Domain.Recon;
using Spectre.Console;
using Spectre.Console.Cli;

namespace Rabits.CLI.Commands;

public sealed class WebSubdomainsSettings : WebDomainSettings
{
    [CommandOption("-c|--concurrency <N>")]
    [DefaultValue(32)]
    public int Concurrency { get; init; } = 32;
}

/// <summary>`rabits web subdomains` — passive DNS-based subdomain enumeration.</summary>
public sealed class WebSubdomainsCommand : AsyncCommand<WebSubdomainsSettings>
{
    private readonly EnumerateSubdomainsHandler _handler;

    public WebSubdomainsCommand(EnumerateSubdomainsHandler handler) => _handler = handler;

    public override async Task<int> ExecuteAsync(CommandContext context, WebSubdomainsSettings settings)
    {
        using var cts = new CancellationTokenSource();
        Console.CancelKeyPress += (_, e) => { e.Cancel = true; cts.Cancel(); };

        IReadOnlyList<Subdomain> found = Array.Empty<Subdomain>();
        var hits = 0;

        await AnsiConsole.Status().Spinner(Spinner.Known.Dots).StartAsync(
            $"Enumerating subdomains of [bold]{Markup.Escape(settings.Domain)}[/]…",
            async ctx =>
            {
                var progress = new Progress<Subdomain>(_ => ctx.Status(
                    $"Enumerating [bold]{Markup.Escape(settings.Domain)}[/] — {Interlocked.Increment(ref hits)} found…"));
                found = await _handler.HandleAsync(settings.Domain, settings.Concurrency, progress, cts.Token);
            });

        if (settings.Json)
        {
            JsonReport.Emit("web.subdomains", settings.Domain,
                found.Select(s => new { name = s.Name, addresses = s.Addresses }));
            return 0;
        }

        if (found.Count == 0)
        {
            AnsiConsole.MarkupLineInterpolated($"[grey]No subdomains resolved for {settings.Domain}.[/]");
            return 0;
        }

        var table = new Table().Border(TableBorder.Rounded)
            .Title($"[bold]{found.Count}[/] subdomain(s) of {Markup.Escape(settings.Domain)}")
            .AddColumn("Subdomain").AddColumn("Addresses");

        foreach (var s in found)
            table.AddRow($"[cyan]{Markup.Escape(s.Name)}[/]", $"[grey]{Markup.Escape(string.Join(", ", s.Addresses))}[/]");

        AnsiConsole.Write(table);
        return 0;
    }
}
