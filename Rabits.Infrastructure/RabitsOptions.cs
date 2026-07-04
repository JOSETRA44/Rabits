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

    /// <summary>Optional external OUI database merged over the embedded starter set (IEEE/Wireshark format).</summary>
    public string? OuiFilePath { get; set; }

    /// <summary>ICMP echo timeout per host, in milliseconds.</summary>
    public int HostProbeTimeoutMs { get; set; } = 800;

    /// <summary>TCP connect timeout per port, in milliseconds.</summary>
    public int PortConnectTimeoutMs { get; set; } = 500;

    /// <summary>Max simultaneous TCP connects inside a single host's port scan.</summary>
    public int PortScanConcurrency { get; set; } = 200;

    /// <summary>DNS query timeout per server, in milliseconds.</summary>
    public int DnsTimeoutMs { get; set; } = 4000;

    /// <summary>WHOIS TCP timeout, in milliseconds.</summary>
    public int WhoisTimeoutMs { get; set; } = 8000;

    /// <summary>HTTP/TLS probe timeout, in milliseconds.</summary>
    public int WebProbeTimeoutMs { get; set; } = 10000;

    /// <summary>Optional external subdomain wordlist (one label per line) replacing the embedded set.</summary>
    public string? SubdomainWordlistPath { get; set; }

    /// <summary>Force the synthetic traffic generator instead of real capture (demos/tests/no Npcap).</summary>
    public bool ForceSimulatedCapture { get; set; }
}
