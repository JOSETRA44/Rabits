using System.Text.RegularExpressions;
using Rabits.Application.Abstractions;
using Rabits.Application.Security;
using Rabits.Domain.Auditing;
using Rabits.Domain.Layer7;
using Rabits.Domain.Operations;

namespace Rabits.Application.Layer7;

/// <summary>
/// Use case: statically hunt for burned-in secrets. Fetches a page and its linked scripts, then runs
/// the pure <see cref="SecretHunter"/> over each. Passive and audited. The CLI complement of the
/// interactive WebView2 session — both share the same detection engine.
/// </summary>
public sealed partial class ScanUrlForSecretsHandler
{
    public const string OperationName = "web.secrets";
    private const int MaxScripts = 40;

    private readonly IResourceFetcher _fetcher;
    private readonly IAuthorizationGuard _guard;
    private readonly IAuditLog _audit;

    public ScanUrlForSecretsHandler(IResourceFetcher fetcher, IAuthorizationGuard guard, IAuditLog audit)
    {
        _fetcher = fetcher;
        _guard = guard;
        _audit = audit;
    }

    public async Task<IReadOnlyList<SecretFinding>> HandleAsync(Uri url, CancellationToken cancellationToken = default)
    {
        var operation = RabitsOperation.Passive(OperationName, url.Host);
        await _guard.AuthorizeAsync(operation, cancellationToken);

        var findings = new List<SecretFinding>();
        var seen = new HashSet<string>();

        try
        {
            var page = await _fetcher.FetchAsync(url, cancellationToken);
            Collect(findings, seen, SecretHunter.Scan(page.Body, url.ToString()));

            var scripts = ExtractScriptUrls(page.Body, url).Take(MaxScripts).ToList();
            foreach (var scriptUrl in scripts)
            {
                cancellationToken.ThrowIfCancellationRequested();
                try
                {
                    var script = await _fetcher.FetchAsync(scriptUrl, cancellationToken);
                    Collect(findings, seen, SecretHunter.Scan(script.Body, scriptUrl.ToString()));
                }
                catch (Exception) when (cancellationToken.IsCancellationRequested == false)
                {
                    // a single unreachable script must not abort the scan
                }
            }

            await _audit.RecordAsync(operation, AuditOutcome.Completed,
                $"{findings.Count} finding(s) across {scripts.Count + 1} resource(s)", cancellationToken);
            return findings;
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            await _audit.RecordAsync(operation, AuditOutcome.Failed, ex.Message, cancellationToken);
            throw;
        }
    }

    private static void Collect(List<SecretFinding> findings, HashSet<string> seen, IReadOnlyList<SecretFinding> batch)
    {
        foreach (var finding in batch)
            if (seen.Add(finding.Key)) findings.Add(finding);
    }

    private static IEnumerable<Uri> ExtractScriptUrls(string html, Uri baseUrl)
    {
        foreach (Match match in ScriptSrc().Matches(html))
        {
            var src = match.Groups[1].Value;
            if (Uri.TryCreate(baseUrl, src, out var abs) &&
                (abs.Scheme == Uri.UriSchemeHttp || abs.Scheme == Uri.UriSchemeHttps))
                yield return abs;
        }
    }

    [GeneratedRegex(@"<script[^>]+src\s*=\s*[""']([^""']+)[""']", RegexOptions.IgnoreCase)]
    private static partial Regex ScriptSrc();
}
