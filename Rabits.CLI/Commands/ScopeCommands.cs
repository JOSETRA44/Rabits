using System.ComponentModel;
using Rabits.Application.Abstractions;
using Rabits.Application.Security;
using Rabits.CLI.Output;
using Rabits.Domain.Auditing;
using Rabits.Domain.Engagement;
using Rabits.Domain.Operations;
using Spectre.Console;
using Spectre.Console.Cli;

namespace Rabits.CLI.Commands;

public sealed class ScopeShowSettings : GlobalSettings
{
    [CommandOption("--json")]
    public bool Json { get; init; }
}

/// <summary>`rabits scope show` — print the current engagement scope.</summary>
public sealed class ScopeShowCommand : Command<ScopeShowSettings>
{
    private readonly IScopePolicy _scope;
    private readonly AuthorizationOptions _auth;
    public ScopeShowCommand(IScopePolicy scope, AuthorizationOptions auth)
    {
        _scope = scope;
        _auth = auth;
    }

    public override int Execute(CommandContext context, ScopeShowSettings settings)
    {
        var scope = _scope.Current;
        if (settings.Json)
        {
            JsonReport.Emit("scope.show", null, new { godMode = _auth.BypassScope, scope = scope is null ? null : Project(scope) });
            return 0;
        }

        if (_auth.BypassScope)
            AnsiConsole.MarkupLine("[bold red on yellow] GOD MODE ACTIVE [/] [yellow]scope validation is disabled — all operations authorized (still audited).[/]");

        if (scope is null)
        {
            AnsiConsole.MarkupLine(_auth.BypassScope
                ? "[grey]No engagement scope loaded (irrelevant while God Mode is active).[/]"
                : "[yellow]No engagement scope loaded — active/intrusive operations are disabled.[/]");
            return 0;
        }

        AnsiConsole.MarkupLineInterpolated($"[bold]{scope.Name}[/]  [grey](max {scope.MaxClassification})[/]");
        var table = new Table().Border(TableBorder.Rounded).AddColumn("Type").AddColumn("Pattern");
        foreach (var r in scope.Rules)
            table.AddRow(r.Type.ToString(), Markup.Escape(r.Pattern));
        AnsiConsole.Write(table);
        return 0;
    }

    internal static object Project(EngagementScope scope) => new
    {
        loaded = true,
        name = scope.Name,
        maxClassification = scope.MaxClassification.ToString(),
        rules = scope.Rules.Select(r => new { type = r.Type.ToString(), pattern = r.Pattern }),
    };
}

public sealed class ScopeAuthorizeSettings : GlobalSettings
{
    [CommandArgument(0, "<TARGET>")]
    [Description("Target to authorize: IP, CIDR, domain, MAC/BSSID or SSID.")]
    public string Target { get; init; } = string.Empty;

    [CommandOption("-c|--class <CLASS>")]
    [Description("Max operation class to permit: passive | active | intrusive.")]
    public string? Classification { get; init; }

    [CommandOption("--json")]
    public bool Json { get; init; }
}

/// <summary>`rabits scope authorize` — add an authorization to the engagement scope (persisted, audited).</summary>
public sealed class ScopeAuthorizeCommand : AsyncCommand<ScopeAuthorizeSettings>
{
    private readonly IScopePolicy _scope;
    private readonly IAuditLog _audit;

    public ScopeAuthorizeCommand(IScopePolicy scope, IAuditLog audit)
    {
        _scope = scope;
        _audit = audit;
    }

    public override async Task<int> ExecuteAsync(CommandContext context, ScopeAuthorizeSettings settings)
    {
        if (string.IsNullOrWhiteSpace(settings.Target))
        {
            AnsiConsole.MarkupLine("[red]A target is required.[/]");
            return 1;
        }

        var rule = ScopeRule.ForTarget(settings.Target);
        var raiseTo = ParseClass(settings.Classification);
        var scope = _scope.Authorize(rule, raiseTo);
        await _audit.RecordAsync(RabitsOperation.Passive("scope.authorize", settings.Target), AuditOutcome.Completed,
            $"authorized {rule.Type} '{rule.Pattern}'" + (raiseTo is { } c ? $"; max→{c}" : string.Empty));

        if (settings.Json)
        {
            JsonReport.Emit("scope.authorize", settings.Target, new
            {
                authorized = new { type = rule.Type.ToString(), pattern = rule.Pattern },
                scope = ScopeShowCommand.Project(scope),
            });
            return 0;
        }

        AnsiConsole.MarkupLineInterpolated(
            $"[green]✓ authorized[/] {rule.Type} [bold]{settings.Target}[/]  [grey](scope now {scope.Rules.Count} rule(s), max {scope.MaxClassification})[/]");
        return 0;
    }

    private static OperationClassification? ParseClass(string? value) => value?.ToLowerInvariant() switch
    {
        "passive" => OperationClassification.Passive,
        "active" => OperationClassification.Active,
        "intrusive" => OperationClassification.Intrusive,
        _ => null,
    };
}

public sealed class ScopeRevokeSettings : GlobalSettings
{
    [CommandArgument(0, "<PATTERN>")]
    [Description("Exact rule pattern to remove.")]
    public string Pattern { get; init; } = string.Empty;
}

/// <summary>`rabits scope revoke` — remove an authorization from the engagement scope.</summary>
public sealed class ScopeRevokeCommand : AsyncCommand<ScopeRevokeSettings>
{
    private readonly IScopePolicy _scope;
    private readonly IAuditLog _audit;

    public ScopeRevokeCommand(IScopePolicy scope, IAuditLog audit)
    {
        _scope = scope;
        _audit = audit;
    }

    public override async Task<int> ExecuteAsync(CommandContext context, ScopeRevokeSettings settings)
    {
        var removed = _scope.Revoke(settings.Pattern);
        if (removed)
        {
            await _audit.RecordAsync(RabitsOperation.Passive("scope.revoke", settings.Pattern),
                AuditOutcome.Completed, $"revoked '{settings.Pattern}'");
            AnsiConsole.MarkupLineInterpolated($"[green]✓ revoked[/] {settings.Pattern}");
        }
        else
        {
            AnsiConsole.MarkupLineInterpolated($"[grey]No rule matching '{settings.Pattern}'.[/]");
        }
        return 0;
    }
}
