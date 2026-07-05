namespace Rabits.Application.Security;

/// <summary>
/// Cross-cutting authorization settings. <see cref="BypassScope"/> ("God Mode") disables the scope
/// check entirely for trusted local/lab use — deliberately explicit and never the default. Note it
/// disables the <b>check</b>, not the audit trail: bypassed operations are still recorded.
/// </summary>
public sealed class AuthorizationOptions
{
    public bool BypassScope { get; init; }
}
