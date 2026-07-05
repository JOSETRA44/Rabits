using System.ComponentModel;
using Spectre.Console.Cli;

namespace Rabits.CLI.Commands;

/// <summary>
/// Options common to every command. These are also pre-scanned in Program.cs to configure the
/// engine before the DI container is built, so they are declared here to keep Spectre happy.
/// </summary>
public class GlobalSettings : CommandSettings
{
    [CommandOption("--scope <PATH>")]
    [Description("Path to the engagement scope file (enables active operations in scope).")]
    public string? ScopePath { get; init; }

    [CommandOption("--audit <PATH>")]
    [Description("Path to the append-only audit trail (JSON Lines).")]
    public string? AuditPath { get; init; }

    [CommandOption("--fake")]
    [Description("Use the built-in sample scanner instead of the real adapter.")]
    public bool Fake { get; init; }

    [CommandOption("--simulate")]
    [Description("Use the synthetic traffic generator instead of real capture.")]
    public bool Simulate { get; init; }

    [CommandOption("--god-mode")]
    [Description("Disable scope validation entirely (trusted local/lab use; still audited).")]
    public bool GodMode { get; init; }
}
