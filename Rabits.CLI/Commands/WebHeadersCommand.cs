using System.ComponentModel;
using System.Text.Json;
using Rabits.Application.Recon;
using Rabits.Domain.Engagement;
using Rabits.Domain.Recon;
using Spectre.Console;
using Spectre.Console.Cli;

namespace Rabits.CLI.Commands;

public sealed class WebHeadersSettings : GlobalSettings
{
    [CommandArgument(0, "<URL>")]
    [Description("Target URL (https assumed if no scheme).")]
    public string Url { get; init; } = string.Empty;

    [CommandOption("--json")]
    public bool Json { get; init; }
}

/// <summary>`rabits web headers` — active HTTP/TLS inspection + security-header audit (scope-gated).</summary>
public sealed class WebHeadersCommand : AsyncCommand<WebHeadersSettings>
{
    private readonly InspectWebEndpointHandler _handler;

    public WebHeadersCommand(InspectWebEndpointHandler handler) => _handler = handler;

    public override async Task<int> ExecuteAsync(CommandContext context, WebHeadersSettings settings)
    {
        WebEndpointInfo info;
        try
        {
            info = await _handler.HandleAsync(settings.Url);
        }
        catch (OutOfScopeException ex)
        {
            AnsiConsole.MarkupLineInterpolated($"[red]Refused — out of scope:[/] {ex.Message}");
            AnsiConsole.MarkupLine("[grey]Add the host to the engagement scope to inspect it.[/]");
            return 3;
        }
        catch (ArgumentException ex)
        {
            AnsiConsole.MarkupLineInterpolated($"[red]{ex.Message}[/]");
            return 1;
        }
        catch (Exception ex)
        {
            AnsiConsole.MarkupLineInterpolated($"[red]Inspection failed:[/] {ex.Message}");
            return 1;
        }

        if (settings.Json)
        {
            Console.WriteLine(JsonSerializer.Serialize(new
            {
                url = info.Url.ToString(),
                status = info.StatusCode,
                server = info.Server,
                poweredBy = info.PoweredBy,
                tls = info.Tls is null ? null : new
                {
                    info.Tls.Subject, info.Tls.Issuer, info.Tls.NotAfter,
                    info.Tls.ChainValid, info.Tls.DaysUntilExpiry, sans = info.Tls.SubjectAltNames,
                },
                headers = info.Headers,
                security = info.SecurityFindings.Select(f => new { f.Header, f.Present, severity = f.Severity.ToString(), f.Detail }),
            }, new JsonSerializerOptions { WriteIndented = true }));
            return 0;
        }

        var statusColour = info.StatusCode < 300 ? "green" : info.StatusCode < 400 ? "yellow" : "red";
        AnsiConsole.MarkupLine($"[bold]{Markup.Escape(info.Url.ToString())}[/]");
        AnsiConsole.MarkupLine($"HTTP [{statusColour}]{info.StatusCode} {Markup.Escape(info.ReasonPhrase ?? "")}[/]" +
                               $"   [grey]Server:[/] {Markup.Escape(info.Server ?? "—")}");
        AnsiConsole.WriteLine();

        if (info.Tls is { } tls)
        {
            var expiry = tls.IsExpired ? $"[red]EXPIRED[/]" : $"{tls.DaysUntilExpiry} days";
            var chain = tls.ChainValid ? "[green]valid[/]" : "[red]untrusted[/]";
            var grid = new Grid().AddColumn().AddColumn();
            grid.AddRow("[grey]Subject[/]", Markup.Escape(tls.Subject));
            grid.AddRow("[grey]Issuer[/]", Markup.Escape(tls.Issuer));
            grid.AddRow("[grey]Valid until[/]", $"{tls.NotAfter:u}  ({expiry})");
            grid.AddRow("[grey]Chain[/]", chain);
            grid.AddRow("[grey]SANs[/]", tls.SubjectAltNames.Count > 0
                ? Markup.Escape(string.Join(", ", tls.SubjectAltNames.Take(8)))
                : "—");
            AnsiConsole.Write(new Panel(grid).Header("TLS certificate").Border(BoxBorder.Rounded));
            AnsiConsole.WriteLine();
        }

        var table = new Table().Border(TableBorder.Rounded).Title("Security headers")
            .AddColumn("Header").AddColumn("Status").AddColumn("Severity").AddColumn("Detail");
        foreach (var f in info.SecurityFindings)
            table.AddRow(
                Markup.Escape(f.Header),
                f.Present ? "[green]✓ present[/]" : "[red]✗ missing[/]",
                Severity(f.Severity),
                Markup.Escape(f.Detail));
        AnsiConsole.Write(table);
        return 0;
    }

    private static string Severity(SecurityFindingSeverity severity) => severity switch
    {
        SecurityFindingSeverity.High => "[red]HIGH[/]",
        SecurityFindingSeverity.Medium => "[darkorange]MEDIUM[/]",
        SecurityFindingSeverity.Low => "[yellow]LOW[/]",
        _ => "[grey]info[/]",
    };
}
