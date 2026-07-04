using Rabits.Application.Abstractions;
using Rabits.Application.Security;
using Rabits.Domain.Auditing;
using Rabits.Domain.Operations;
using Rabits.Domain.Recon;

namespace Rabits.Application.Recon;

/// <summary>
/// Use case: inspect a web endpoint's HTTP response, TLS certificate and security headers. This is
/// an <b>active</b> operation (it connects to the target), so the host must be in the engagement scope.
/// </summary>
public sealed class InspectWebEndpointHandler
{
    public const string OperationName = "web.inspect";

    private readonly IWebProbe _probe;
    private readonly IAuthorizationGuard _guard;
    private readonly IAuditLog _audit;

    public InspectWebEndpointHandler(IWebProbe probe, IAuthorizationGuard guard, IAuditLog audit)
    {
        _probe = probe;
        _guard = guard;
        _audit = audit;
    }

    public async Task<WebEndpointInfo> HandleAsync(string url, CancellationToken cancellationToken = default)
    {
        if (!TryNormalizeUrl(url, out var uri))
            throw new ArgumentException($"'{url}' is not a valid http(s) URL.", nameof(url));

        var operation = RabitsOperation.Active(OperationName, uri.Host);
        await _guard.AuthorizeAsync(operation, cancellationToken);

        try
        {
            var info = await _probe.InspectAsync(uri, cancellationToken);
            await _audit.RecordAsync(operation, AuditOutcome.Completed,
                $"HTTP {info.StatusCode}", cancellationToken);
            return info;
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            await _audit.RecordAsync(operation, AuditOutcome.Failed, ex.Message, cancellationToken);
            throw;
        }
    }

    private static bool TryNormalizeUrl(string url, out Uri uri)
    {
        var candidate = url.Contains("://", StringComparison.Ordinal) ? url : $"https://{url}";
        return Uri.TryCreate(candidate, UriKind.Absolute, out uri!)
               && (uri.Scheme == Uri.UriSchemeHttp || uri.Scheme == Uri.UriSchemeHttps);
    }
}
