namespace Rabits.Domain.Auth;

/// <summary>A username/password pair to be tested against an authentication endpoint.</summary>
public sealed record Credential(string Username, string Password)
{
    /// <summary>Password masked for display/logging (keeps length, hides the value).</summary>
    public string MaskedPassword => Password.Length switch
    {
        0 => "(empty)",
        <= 2 => new string('•', Password.Length),
        _ => $"{Password[0]}{new string('•', Password.Length - 2)}{Password[^1]}",
    };

    public override string ToString() => $"{Username}:{MaskedPassword}";
}
