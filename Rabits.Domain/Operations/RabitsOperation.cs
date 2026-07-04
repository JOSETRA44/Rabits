namespace Rabits.Domain.Operations;

/// <summary>
/// Describes an operation the engine is about to perform, so the authorization gate and the
/// audit log can reason about it uniformly. Targets are free-form (an IP, CIDR, domain, or BSSID).
/// </summary>
public sealed record RabitsOperation(string Name, OperationClassification Classification, string Target)
{
    /// <summary>A passive operation carries no meaningful target constraint (nothing is touched).</summary>
    public static RabitsOperation Passive(string name, string target = "*")
        => new(name, OperationClassification.Passive, target);

    public static RabitsOperation Active(string name, string target)
        => new(name, OperationClassification.Active, target);

    public static RabitsOperation Intrusive(string name, string target)
        => new(name, OperationClassification.Intrusive, target);
}
