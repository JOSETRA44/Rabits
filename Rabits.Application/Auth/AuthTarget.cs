using Rabits.Domain.Auth;

namespace Rabits.Application.Auth;

/// <summary>
/// Describes an authentication endpoint and how to tell a successful login from a failed one.
/// Detection precedence in probes: success status codes → failure marker → success marker.
/// </summary>
public sealed record AuthTarget
{
    public required AuthProtocol Protocol { get; init; }
    public required Uri Url { get; init; }

    public string UserField { get; init; } = "username";
    public string PasswordField { get; init; } = "password";

    /// <summary>Static extra form fields sent with every POST (e.g. CSRF token, "login=1").</summary>
    public IReadOnlyDictionary<string, string> ExtraFields { get; init; } = new Dictionary<string, string>();

    /// <summary>If set, these response status codes indicate success (e.g. 302 redirect).</summary>
    public IReadOnlyList<int> SuccessStatusCodes { get; init; } = Array.Empty<int>();

    /// <summary>If the response body contains this text, the attempt is a failure.</summary>
    public string? FailureBodyContains { get; init; }

    /// <summary>If the response body contains this text, the attempt is a success.</summary>
    public string? SuccessBodyContains { get; init; }
}
