using Rabits.Domain.Engagement;

namespace Rabits.Application.Abstractions;

/// <summary>
/// Supplies the active <see cref="EngagementScope"/>. Returns null when no scope file is loaded,
/// in which case the authorization gate denies every non-passive operation.
/// </summary>
public interface IScopePolicy
{
    EngagementScope? Current { get; }
}
