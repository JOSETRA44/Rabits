using Rabits.Application.Abstractions;

namespace Rabits.Infrastructure.Layer7;

/// <summary>Downloads a resource over HTTP for static analysis. Reads text-like bodies only (capped).</summary>
public sealed class HttpResourceFetcher : IResourceFetcher
{
    private const long MaxBodyBytes = 16 * 1024 * 1024;
    private readonly int _timeoutMs;

    public HttpResourceFetcher(int timeoutMs = 10000) => _timeoutMs = timeoutMs;

    public async Task<FetchedResource> FetchAsync(Uri url, CancellationToken cancellationToken = default)
    {
        using var handler = new HttpClientHandler
        {
            AllowAutoRedirect = true,
            ServerCertificateCustomValidationCallback = (_, _, _, _) => true,
        };
        using var client = new HttpClient(handler) { Timeout = TimeSpan.FromMilliseconds(_timeoutMs) };
        client.DefaultRequestHeaders.UserAgent.ParseAdd("Rabits/1.0 (+recon)");

        using var response = await client.GetAsync(url, HttpCompletionOption.ResponseHeadersRead, cancellationToken);
        var contentType = response.Content.Headers.ContentType?.MediaType ?? string.Empty;
        var finalUrl = response.RequestMessage?.RequestUri ?? url;

        if (response.Content.Headers.ContentLength is > MaxBodyBytes || !IsTextLike(contentType))
            return new FetchedResource(finalUrl, contentType, string.Empty);

        var body = await response.Content.ReadAsStringAsync(cancellationToken);
        return new FetchedResource(finalUrl, contentType, body);
    }

    private static bool IsTextLike(string contentType)
    {
        if (contentType.Length == 0) return true; // unknown — attempt to read
        return contentType.StartsWith("text/", StringComparison.OrdinalIgnoreCase)
               || contentType.Contains("javascript", StringComparison.OrdinalIgnoreCase)
               || contentType.Contains("json", StringComparison.OrdinalIgnoreCase)
               || contentType.Contains("xml", StringComparison.OrdinalIgnoreCase)
               || contentType.Contains("html", StringComparison.OrdinalIgnoreCase);
    }
}
