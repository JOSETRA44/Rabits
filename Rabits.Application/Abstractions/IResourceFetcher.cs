namespace Rabits.Application.Abstractions;

/// <summary>A downloaded web resource: its final URL, content type and text body (empty if binary).</summary>
public sealed record FetchedResource(Uri Url, string ContentType, string Body);

/// <summary>Downloads a web resource for static analysis (passive — a single GET).</summary>
public interface IResourceFetcher
{
    Task<FetchedResource> FetchAsync(Uri url, CancellationToken cancellationToken = default);
}
