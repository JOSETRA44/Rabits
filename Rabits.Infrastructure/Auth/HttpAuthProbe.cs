using System.Diagnostics;
using System.Net.Http.Headers;
using System.Text;
using Rabits.Application.Abstractions;
using Rabits.Application.Auth;
using Rabits.Domain.Auth;

namespace Rabits.Infrastructure.Auth;

/// <summary>
/// Tests credentials against an HTTP endpoint (Basic auth or form POST). Uses a fixed, identifiable
/// User-Agent (no evasion) and does not follow redirects, so a login redirect can be used as a
/// success signal. Success/failure detection follows the target's configured precedence.
/// </summary>
public sealed class HttpAuthProbe : IAuthProbe
{
    private readonly int _timeoutMs;

    public HttpAuthProbe(int timeoutMs = 10000) => _timeoutMs = timeoutMs;

    public async Task<CredentialAttemptResult> TryAsync(
        AuthTarget target, Credential credential, CancellationToken cancellationToken = default)
    {
        var stopwatch = Stopwatch.StartNew();

        using var handler = new HttpClientHandler
        {
            AllowAutoRedirect = false,
            ServerCertificateCustomValidationCallback = (_, _, _, _) => true, // audit internal/self-signed too
        };
        using var client = new HttpClient(handler) { Timeout = TimeSpan.FromMilliseconds(_timeoutMs) };
        client.DefaultRequestHeaders.UserAgent.ParseAdd("Rabits/1.0 (+credential-audit)");

        try
        {
            using var response = target.Protocol == AuthProtocol.HttpBasic
                ? await SendBasicAsync(client, target, credential, cancellationToken)
                : await SendFormAsync(client, target, credential, cancellationToken);

            var status = (int)response.StatusCode;
            var result = await ClassifyAsync(target, response, status, cancellationToken);

            return new CredentialAttemptResult
            {
                Credential = credential,
                Result = result,
                StatusCode = status,
                Elapsed = stopwatch.Elapsed,
                Detail = $"HTTP {status}",
            };
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex)
        {
            return new CredentialAttemptResult
            {
                Credential = credential,
                Result = AuthResult.Error,
                Elapsed = stopwatch.Elapsed,
                Detail = ex.Message,
            };
        }
    }

    private static Task<HttpResponseMessage> SendBasicAsync(
        HttpClient client, AuthTarget target, Credential credential, CancellationToken ct)
    {
        var request = new HttpRequestMessage(HttpMethod.Get, target.Url);
        var token = Convert.ToBase64String(Encoding.UTF8.GetBytes($"{credential.Username}:{credential.Password}"));
        request.Headers.Authorization = new AuthenticationHeaderValue("Basic", token);
        return client.SendAsync(request, ct);
    }

    private static Task<HttpResponseMessage> SendFormAsync(
        HttpClient client, AuthTarget target, Credential credential, CancellationToken ct)
    {
        var fields = new Dictionary<string, string>(target.ExtraFields)
        {
            [target.UserField] = credential.Username,
            [target.PasswordField] = credential.Password,
        };
        return client.PostAsync(target.Url, new FormUrlEncodedContent(fields), ct);
    }

    private static async Task<AuthResult> ClassifyAsync(
        AuthTarget target, HttpResponseMessage response, int status, CancellationToken ct)
    {
        // 1) Explicit success status codes take priority (e.g. a 302 redirect after login).
        if (target.SuccessStatusCodes.Count > 0)
            return target.SuccessStatusCodes.Contains(status) ? AuthResult.Success : AuthResult.Failure;

        // 2) Body markers.
        if (target.FailureBodyContains is not null || target.SuccessBodyContains is not null)
        {
            var body = await response.Content.ReadAsStringAsync(ct);
            if (target.FailureBodyContains is not null)
                return body.Contains(target.FailureBodyContains, StringComparison.OrdinalIgnoreCase)
                    ? AuthResult.Failure : AuthResult.Success;
            return body.Contains(target.SuccessBodyContains!, StringComparison.OrdinalIgnoreCase)
                ? AuthResult.Success : AuthResult.Failure;
        }

        // 3) Protocol defaults.
        if (target.Protocol == AuthProtocol.HttpBasic)
            return status is 401 or 403 ? AuthResult.Failure : AuthResult.Success;

        // Form default: a redirect usually means the login was accepted; a 200 re-renders the form.
        return status is >= 300 and < 400 ? AuthResult.Success : AuthResult.Failure;
    }
}
