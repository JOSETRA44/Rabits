using Rabits.Domain.Operations;

namespace Rabits.Domain.Engagement;

/// <summary>
/// The rules of engagement for an authorized red-team assessment: which targets may be touched,
/// during which time window, at what rate, and which classes of operation are permitted.
/// This is the single source of truth the authorization gate consults before any active action.
/// </summary>
public sealed class EngagementScope
{
    public required string Name { get; init; }
    public IReadOnlyList<ScopeRule> Rules { get; init; } = Array.Empty<ScopeRule>();

    /// <summary>Inclusive start of the authorized window; null means "no lower bound".</summary>
    public DateTimeOffset? StartsAt { get; init; }

    /// <summary>Inclusive end of the authorized window; null means "no upper bound".</summary>
    public DateTimeOffset? EndsAt { get; init; }

    /// <summary>Optional client-side rate cap for active operations.</summary>
    public int? MaxRequestsPerSecond { get; init; }

    /// <summary>The highest operation class this engagement authorizes. Defaults to Active.</summary>
    public OperationClassification MaxClassification { get; init; } = OperationClassification.Active;

    public bool IsWithinWindow(DateTimeOffset now)
        => (StartsAt is null || now >= StartsAt) && (EndsAt is null || now <= EndsAt);

    /// <summary>
    /// Pure authorization decision. Passive operations are always allowed. Active/Intrusive
    /// operations require an open window, a permitted classification, and a matching target rule.
    /// </summary>
    public AuthorizationResult Evaluate(RabitsOperation operation, DateTimeOffset now)
    {
        if (operation.Classification == OperationClassification.Passive)
            return AuthorizationResult.Allow("passive operation");

        if (!IsWithinWindow(now))
            return AuthorizationResult.Deny($"outside the authorized window ({Describe(StartsAt)} – {Describe(EndsAt)})");

        if (operation.Classification > MaxClassification)
            return AuthorizationResult.Deny($"'{operation.Classification}' exceeds the engagement's max classification '{MaxClassification}'");

        return Rules.Any(r => r.Matches(operation.Target))
            ? AuthorizationResult.Allow($"target '{operation.Target}' is in scope")
            : AuthorizationResult.Deny($"target '{operation.Target}' is not covered by any scope rule");
    }

    private static string Describe(DateTimeOffset? bound) => bound?.ToString("u") ?? "∞";
}
