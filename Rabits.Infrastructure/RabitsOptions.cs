namespace Rabits.Infrastructure;

/// <summary>Configuration for the Rabits engine, supplied by whichever frontend composes it.</summary>
public sealed class RabitsOptions
{
    /// <summary>Path to the engagement scope file (JSON). Absent file ⇒ active operations disabled.</summary>
    public string ScopeFilePath { get; set; } = "scope.json";

    /// <summary>Path to the append-only audit trail (JSON Lines).</summary>
    public string AuditLogPath { get; set; } = "rabits-audit.jsonl";

    /// <summary>Force the sample scanner even on a Windows host with a real adapter (demos/tests).</summary>
    public bool ForceFakeScanner { get; set; }

    /// <summary>Ask the adapter to run a fresh scan before reading the BSS list.</summary>
    public bool TriggerWifiScan { get; set; } = true;

    /// <summary>How long to let a triggered scan settle before reading results.</summary>
    public int WifiScanSettleSeconds { get; set; } = 3;
}
