using System.Collections.Concurrent;
using System.Diagnostics;
using Rabits.Application.Abstractions;
using Rabits.Application.Security;
using Rabits.Domain.Auditing;
using Rabits.Domain.Auth;
using Rabits.Domain.Operations;

namespace Rabits.Application.Auth;

/// <summary>
/// Use case: audit credential robustness against an authentication endpoint using a dictionary.
/// This is an <b>Intrusive</b> operation — the strongest classification — so the target must be in
/// scope and the engagement must explicitly permit intrusive actions, or the gate refuses. Runs are
/// concurrency-bounded, rate-limited to the scope's cap, capped by MaxAttempts, and fully audited.
/// </summary>
public sealed class CredentialAuditHandler
{
    public const string OperationName = "auth.http";

    private readonly IAuthProbe _probe;
    private readonly IAuthorizationGuard _guard;
    private readonly IAuditLog _audit;
    private readonly IScopePolicy _scope;

    public CredentialAuditHandler(IAuthProbe probe, IAuthorizationGuard guard, IAuditLog audit, IScopePolicy scope)
    {
        _probe = probe;
        _guard = guard;
        _audit = audit;
        _scope = scope;
    }

    public async Task<CredentialAuditSummary> HandleAsync(
        CredentialAuditRequest request,
        IProgress<CredentialAttemptResult>? progress = null,
        CancellationToken cancellationToken = default)
    {
        var operation = RabitsOperation.Intrusive(OperationName, request.Target.Url.Host);
        await _guard.AuthorizeAsync(operation, cancellationToken);

        var credentials = BuildCredentials(request).Take(request.MaxAttempts).ToList();
        var stopwatch = Stopwatch.StartNew();

        using var linked = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        var token = linked.Token;
        using var throttle = new SemaphoreSlim(Math.Max(1, request.Concurrency));

        var rps = _scope.Current?.MaxRequestsPerSecond;
        using var limiter = rps is > 0 ? new RateLimiter(rps.Value) : null;

        var successes = new ConcurrentBag<Credential>();
        var attempted = 0;
        var errors = 0;
        var stoppedEarly = false;

        var tasks = credentials.Select(async credential =>
        {
            try { await throttle.WaitAsync(token); }
            catch (OperationCanceledException) { return; }

            try
            {
                if (token.IsCancellationRequested) return;
                if (limiter is not null) await limiter.WaitAsync(token);

                var result = await _probe.TryAsync(request.Target, credential, token);
                Interlocked.Increment(ref attempted);
                if (result.Result == AuthResult.Error) Interlocked.Increment(ref errors);

                if (result.IsSuccess)
                {
                    successes.Add(credential);
                    await _audit.RecordAsync(operation, AuditOutcome.Completed,
                        $"VALID credential found: {credential.Username}:{credential.Password}", CancellationToken.None);
                    if (request.StopOnSuccess)
                    {
                        stoppedEarly = true;
                        linked.Cancel();
                    }
                }

                progress?.Report(result);
            }
            catch (OperationCanceledException) { /* stopped */ }
            finally
            {
                throttle.Release();
            }
        });

        await Task.WhenAll(tasks);
        stopwatch.Stop();

        var summary = new CredentialAuditSummary
        {
            Attempted = attempted,
            Elapsed = stopwatch.Elapsed,
            Successes = successes.ToList(),
            Errors = errors,
            StoppedEarly = stoppedEarly,
        };

        await _audit.RecordAsync(operation, AuditOutcome.Completed,
            $"{summary.Attempted} attempt(s), {summary.Successes.Count} valid, {summary.Errors} error(s)",
            CancellationToken.None);

        return summary;
    }

    private static IEnumerable<Credential> BuildCredentials(CredentialAuditRequest request)
    {
        foreach (var username in request.Usernames)
            foreach (var password in request.Passwords)
                yield return new Credential(username, password);
    }
}
