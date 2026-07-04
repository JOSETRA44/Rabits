namespace Rabits.Domain.Engagement;

/// <summary>The outcome of evaluating an operation against an engagement scope.</summary>
public sealed record AuthorizationResult(bool IsAuthorized, string Reason)
{
    public static AuthorizationResult Allow(string reason) => new(true, reason);
    public static AuthorizationResult Deny(string reason) => new(false, reason);
}
