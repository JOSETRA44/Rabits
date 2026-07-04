namespace Rabits.Domain.Auth;

/// <summary>Outcome of testing a single credential.</summary>
public enum AuthResult
{
    /// <summary>Authentication succeeded — the credential is valid.</summary>
    Success,
    /// <summary>Authentication was rejected — the credential is invalid.</summary>
    Failure,
    /// <summary>The attempt could not be completed (network/timeout/ambiguous response).</summary>
    Error,
}

/// <summary>The result of a single authentication attempt.</summary>
public sealed record CredentialAttemptResult
{
    public required Credential Credential { get; init; }
    public required AuthResult Result { get; init; }
    public int? StatusCode { get; init; }
    public TimeSpan Elapsed { get; init; }
    public string Detail { get; init; } = string.Empty;

    public bool IsSuccess => Result == AuthResult.Success;
}

/// <summary>How the target authentication endpoint is spoken to.</summary>
public enum AuthProtocol
{
    /// <summary>HTTP Basic authentication (Authorization header).</summary>
    HttpBasic,
    /// <summary>HTML form login (POST of form-encoded fields).</summary>
    HttpForm,
}
