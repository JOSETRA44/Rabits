namespace Rabits.Domain.Recon;

/// <summary>Result of inspecting a web endpoint: HTTP response metadata, TLS, and header findings.</summary>
public sealed record WebEndpointInfo
{
    public required Uri Url { get; init; }
    public required int StatusCode { get; init; }
    public string? ReasonPhrase { get; init; }
    public string? Server { get; init; }
    public string? PoweredBy { get; init; }
    public IReadOnlyDictionary<string, string> Headers { get; init; } = new Dictionary<string, string>();
    public TlsCertificateInfo? Tls { get; init; }
    public IReadOnlyList<SecurityHeaderFinding> SecurityFindings { get; init; } = Array.Empty<SecurityHeaderFinding>();

    public bool IsHttps => Url.Scheme == Uri.UriSchemeHttps;
}
