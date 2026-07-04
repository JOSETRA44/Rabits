namespace Rabits.Domain.Layer7;

/// <summary>How the browser classified a captured network resource.</summary>
public enum ResourceType
{
    Other = 0,
    Document,
    Script,
    Stylesheet,
    Xhr,
    Fetch,
    Image,
    Font,
    WebSocket,
    Media,
}

/// <summary>
/// An immutable summary of one request/response observed while the operator browses the target.
/// Lightweight (no bodies retained) so a busy SPA session stays memory-bounded.
/// </summary>
public sealed record HttpExchange
{
    public required string Method { get; init; }
    public required string Url { get; init; }
    public required string Host { get; init; }
    public int StatusCode { get; init; }
    public ResourceType ResourceType { get; init; } = ResourceType.Other;
    public string MimeType { get; init; } = string.Empty;
    public long ResponseSize { get; init; }
    public double DurationMs { get; init; }
    public DateTimeOffset Timestamp { get; init; } = DateTimeOffset.Now;

    /// <summary>Short preview of the request payload (truncated) for API bodies.</summary>
    public string RequestBodyPreview { get; init; } = string.Empty;

    /// <summary>The path without scheme/host/query, useful for endpoint de-duplication.</summary>
    public string Path { get; init; } = string.Empty;

    /// <summary>Heuristic: is this an application/API call rather than a static asset?</summary>
    public bool IsApiLike =>
        ResourceType is ResourceType.Xhr or ResourceType.Fetch
        || MimeType.Contains("json", StringComparison.OrdinalIgnoreCase)
        || MimeType.Contains("graphql", StringComparison.OrdinalIgnoreCase)
        || Path.Contains("/api/", StringComparison.OrdinalIgnoreCase)
        || Path.Contains("/graphql", StringComparison.OrdinalIgnoreCase)
        || Path.Contains("/rest/", StringComparison.OrdinalIgnoreCase);
}
