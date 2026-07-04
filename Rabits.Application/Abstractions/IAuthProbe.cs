using Rabits.Application.Auth;
using Rabits.Domain.Auth;

namespace Rabits.Application.Abstractions;

/// <summary>Tests a single credential against an authentication endpoint.</summary>
public interface IAuthProbe
{
    Task<CredentialAttemptResult> TryAsync(
        AuthTarget target, Credential credential, CancellationToken cancellationToken = default);
}
