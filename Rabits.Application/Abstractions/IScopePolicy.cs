using Rabits.Domain.Engagement;
using Rabits.Domain.Operations;

namespace Rabits.Application.Abstractions;

/// <summary>
/// Supplies the active <see cref="EngagementScope"/> and lets it grow during a live session. The
/// authorization gate reads <see cref="Current"/> on every operation, so an authorization added
/// mid-session takes effect immediately — no restart. Returns null when no scope is loaded, in which
/// case the gate denies every non-passive operation.
/// </summary>
public interface IScopePolicy
{
    EngagementScope? Current { get; }

    /// <summary>
    /// Records an operator authorization for <paramref name="rule"/>, optionally raising the
    /// engagement's max classification, and persists it. Creates an ad-hoc engagement if none exists.
    /// Returns the updated scope. This is the conversational "you're authorized for X" path.
    /// </summary>
    EngagementScope Authorize(ScopeRule rule, OperationClassification? raiseTo = null);

    /// <summary>Removes any rule matching <paramref name="pattern"/>; returns true if something changed.</summary>
    bool Revoke(string pattern);

    /// <summary>Forces a re-read of the backing store.</summary>
    void Reload();
}
