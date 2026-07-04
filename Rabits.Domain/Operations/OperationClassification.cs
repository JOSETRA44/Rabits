namespace Rabits.Domain.Operations;

/// <summary>
/// How intrusive an operation is against a target. This drives the authorization gate:
/// passive observation is always allowed; anything that touches a target is scope-gated.
/// </summary>
public enum OperationClassification
{
    /// <summary>Listen-only, no frames sent to the target (e.g. Wi-Fi scan, DNS/WHOIS lookups).</summary>
    Passive = 0,

    /// <summary>Sends traffic to the target but is non-destructive (e.g. port scan, banner grab).</summary>
    Active = 1,

    /// <summary>Attempts to gain access or degrade a target (e.g. brute force, injection).</summary>
    Intrusive = 2,
}
