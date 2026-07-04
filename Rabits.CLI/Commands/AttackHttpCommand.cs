using System.ComponentModel;
using Rabits.Application.Abstractions;
using Rabits.Application.Auth;
using Rabits.Domain.Auth;
using Rabits.Domain.Engagement;
using Spectre.Console;
using Spectre.Console.Cli;

namespace Rabits.CLI.Commands;

public sealed class AttackHttpSettings : GlobalSettings
{
    [CommandArgument(0, "<URL>")]
    [Description("Login endpoint URL.")]
    public string Url { get; init; } = string.Empty;

    [CommandOption("--basic")]
    [Description("Use HTTP Basic auth instead of form POST.")]
    public bool Basic { get; init; }

    [CommandOption("-u|--user <USER>")]
    [Description("Single username to test.")]
    public string? User { get; init; }

    [CommandOption("--users <FILE>")]
    [Description("File of usernames (one per line).")]
    public string? UsersFile { get; init; }

    [CommandOption("-w|--wordlist <FILE>")]
    [Description("Password wordlist file (default: embedded common list).")]
    public string? Wordlist { get; init; }

    [CommandOption("--user-field <NAME>")]
    [DefaultValue("username")]
    public string UserField { get; init; } = "username";

    [CommandOption("--pass-field <NAME>")]
    [DefaultValue("password")]
    public string PassField { get; init; } = "password";

    [CommandOption("--success-status <CODE>")]
    [Description("HTTP status that indicates success (e.g. 302).")]
    public int? SuccessStatus { get; init; }

    [CommandOption("--fail-contains <TEXT>")]
    [Description("Response body text that indicates a failed login.")]
    public string? FailContains { get; init; }

    [CommandOption("--success-contains <TEXT>")]
    [Description("Response body text that indicates a successful login.")]
    public string? SuccessContains { get; init; }

    [CommandOption("-c|--concurrency <N>")]
    [DefaultValue(8)]
    public int Concurrency { get; init; } = 8;

    [CommandOption("--no-stop")]
    [Description("Keep testing after the first valid credential is found.")]
    public bool NoStop { get; init; }

    [CommandOption("--max <N>")]
    [DefaultValue(5000)]
    public int Max { get; init; } = 5000;
}

/// <summary>`rabits attack http` — dictionary credential audit against an HTTP login (Intrusive, scope-gated).</summary>
public sealed class AttackHttpCommand : AsyncCommand<AttackHttpSettings>
{
    private readonly CredentialAuditHandler _handler;
    private readonly ICredentialWordlist _wordlist;

    public AttackHttpCommand(CredentialAuditHandler handler, ICredentialWordlist wordlist)
    {
        _handler = handler;
        _wordlist = wordlist;
    }

    public override async Task<int> ExecuteAsync(CommandContext context, AttackHttpSettings settings)
    {
        if (!TryNormalizeUrl(settings.Url, out var uri))
        {
            AnsiConsole.MarkupLineInterpolated($"[red]Invalid URL:[/] {settings.Url}");
            return 1;
        }

        var usernames = LoadUsernames(settings);
        var passwords = settings.Wordlist is { } file && File.Exists(file)
            ? File.ReadAllLines(file).Where(l => l.Length > 0 && !l.StartsWith('#')).ToList()
            : _wordlist.Passwords;

        var target = new AuthTarget
        {
            Protocol = settings.Basic ? AuthProtocol.HttpBasic : AuthProtocol.HttpForm,
            Url = uri,
            UserField = settings.UserField,
            PasswordField = settings.PassField,
            SuccessStatusCodes = settings.SuccessStatus is { } s ? new[] { s } : Array.Empty<int>(),
            FailureBodyContains = settings.FailContains,
            SuccessBodyContains = settings.SuccessContains,
        };

        var request = new CredentialAuditRequest
        {
            Target = target,
            Usernames = usernames,
            Passwords = passwords,
            Concurrency = settings.Concurrency,
            StopOnSuccess = !settings.NoStop,
            MaxAttempts = settings.Max,
        };

        var total = Math.Min(usernames.Count * passwords.Count, settings.Max);
        using var cts = new CancellationTokenSource();
        Console.CancelKeyPress += (_, e) => { e.Cancel = true; cts.Cancel(); };

        var attempted = 0;
        var progress = new Progress<CredentialAttemptResult>(_ => Interlocked.Increment(ref attempted));

        CredentialAuditSummary summary;
        try
        {
            summary = await AnsiConsole.Status().Spinner(Spinner.Known.Dots).StartAsync(
                $"Auditing [bold]{Markup.Escape(uri.Host)}[/] — up to {total} credential(s)…",
                async _ => await _handler.HandleAsync(request, progress, cts.Token));
        }
        catch (OutOfScopeException ex)
        {
            AnsiConsole.MarkupLineInterpolated($"[red]Refused — out of scope:[/] {ex.Message}");
            AnsiConsole.MarkupLine("[grey]Credential audit is Intrusive: the scope must list this host AND set \"maxClassification\": \"Intrusive\".[/]");
            return 3;
        }

        Render(summary, uri.Host);
        return summary.AnySuccess ? 0 : 0;
    }

    private static void Render(CredentialAuditSummary summary, string host)
    {
        if (summary.AnySuccess)
        {
            var table = new Table().Border(TableBorder.Rounded).Title("[bold green]VALID CREDENTIALS FOUND[/]")
                .AddColumn("Username").AddColumn("Password");
            foreach (var c in summary.Successes)
                table.AddRow($"[bold green]{Markup.Escape(c.Username)}[/]", $"[bold green]{Markup.Escape(c.Password)}[/]");
            AnsiConsole.Write(table);
        }
        else
        {
            AnsiConsole.MarkupLineInterpolated($"[grey]No valid credentials found for {host}.[/]");
        }

        AnsiConsole.MarkupLine(
            $"[grey]Attempted[/] {summary.Attempted}  " +
            $"[grey]failures[/] {summary.Failures}  " +
            $"[grey]errors[/] {summary.Errors}  " +
            $"[grey]elapsed[/] {summary.Elapsed.TotalSeconds:0.0}s" +
            (summary.StoppedEarly ? "  [green](stopped on success)[/]" : ""));
    }

    private static IReadOnlyList<string> LoadUsernames(AttackHttpSettings settings)
    {
        if (settings.UsersFile is { } file && File.Exists(file))
            return File.ReadAllLines(file).Where(l => l.Length > 0 && !l.StartsWith('#')).ToList();
        return new[] { settings.User ?? "admin" };
    }

    private static bool TryNormalizeUrl(string url, out Uri uri)
    {
        var candidate = url.Contains("://", StringComparison.Ordinal) ? url : $"https://{url}";
        return Uri.TryCreate(candidate, UriKind.Absolute, out uri!)
               && (uri.Scheme == Uri.UriSchemeHttp || uri.Scheme == Uri.UriSchemeHttps);
    }
}
