using System.ComponentModel;
using System.Text.Json;
using Rabits.Application.Layer7;
using Rabits.Domain.Engagement;
using Rabits.Domain.Layer7;
using Rabits.Domain.Recon;
using Spectre.Console;
using Spectre.Console.Cli;

namespace Rabits.CLI.Commands;

public sealed class WebSecretsSettings : GlobalSettings
{
    [CommandArgument(0, "<URL>")]
    [Description("Page URL to scan (its linked scripts are scanned too).")]
    public string Url { get; init; } = string.Empty;

    [CommandOption("--json")]
    public bool Json { get; init; }
}

/// <summary>`rabits web secrets` — static secret hunting over a page and its scripts (passive).</summary>
public sealed class WebSecretsCommand : AsyncCommand<WebSecretsSettings>
{
    private readonly ScanUrlForSecretsHandler _handler;

    public WebSecretsCommand(ScanUrlForSecretsHandler handler) => _handler = handler;

    public override async Task<int> ExecuteAsync(CommandContext context, WebSecretsSettings settings)
    {
        if (!TryNormalizeUrl(settings.Url, out var uri))
        {
            AnsiConsole.MarkupLineInterpolated($"[red]Invalid URL:[/] {settings.Url}");
            return 1;
        }

        IReadOnlyList<SecretFinding> findings;
        try
        {
            findings = await AnsiConsole.Status().Spinner(Spinner.Known.Dots)
                .StartAsync($"Hunting secrets on [bold]{Markup.Escape(uri.Host)}[/]…", async _ => await _handler.HandleAsync(uri));
        }
        catch (OutOfScopeException ex)
        {
            AnsiConsole.MarkupLineInterpolated($"[red]Refused — out of scope:[/] {ex.Message}");
            return 3;
        }

        if (settings.Json)
        {
            Console.WriteLine(JsonSerializer.Serialize(
                findings.Select(f => new { f.RuleName, f.Category, severity = f.Severity.ToString(), match = f.RedactedMatch, f.Source, f.Entropy }),
                new JsonSerializerOptions { WriteIndented = true }));
            return 0;
        }

        if (findings.Count == 0)
        {
            AnsiConsole.MarkupLineInterpolated($"[green]No secrets found on {uri.Host}.[/]");
            return 0;
        }

        var table = new Table().Border(TableBorder.Rounded)
            .Title($"[bold]{findings.Count}[/] potential secret(s)")
            .AddColumn("Severity").AddColumn("Rule").AddColumn("Match").AddColumn("Source");

        foreach (var f in findings.OrderByDescending(f => f.Severity))
            table.AddRow(
                Severity(f.Severity),
                Markup.Escape(f.RuleName),
                $"[grey]{Markup.Escape(f.RedactedMatch)}[/]",
                $"[grey]{Markup.Escape(Shorten(f.Source))}[/]");

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

    private static string Shorten(string url) => url.Length > 60 ? "…" + url[^57..] : url;

    private static bool TryNormalizeUrl(string url, out Uri uri)
    {
        var candidate = url.Contains("://", StringComparison.Ordinal) ? url : $"https://{url}";
        return Uri.TryCreate(candidate, UriKind.Absolute, out uri!)
               && (uri.Scheme == Uri.UriSchemeHttp || uri.Scheme == Uri.UriSchemeHttps);
    }
}
