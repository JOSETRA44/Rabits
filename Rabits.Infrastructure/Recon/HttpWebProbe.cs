using System.Security.Cryptography.X509Certificates;
using Rabits.Application.Abstractions;
using Rabits.Domain.Recon;

namespace Rabits.Infrastructure.Recon;

/// <summary>
/// Inspects a web endpoint with <see cref="HttpClient"/>: captures status, headers, the TLS
/// certificate (even when invalid, for reporting) and runs the security-header analysis.
/// </summary>
public sealed class HttpWebProbe : IWebProbe
{
    private readonly int _timeoutMs;

    public HttpWebProbe(int timeoutMs = 10000) => _timeoutMs = timeoutMs;

    public async Task<WebEndpointInfo> InspectAsync(Uri url, CancellationToken cancellationToken = default)
    {
        X509Certificate2? capturedCert = null;
        var chainValid = false;

        using var handler = new HttpClientHandler
        {
            AllowAutoRedirect = false,
            ServerCertificateCustomValidationCallback = (_, cert, _, errors) =>
            {
                if (cert is not null) capturedCert = new X509Certificate2(cert.RawData);
                chainValid = errors == System.Net.Security.SslPolicyErrors.None;
                return true; // inspect the endpoint even if the certificate is untrusted
            },
        };

        using var client = new HttpClient(handler);
        client.Timeout = TimeSpan.FromMilliseconds(_timeoutMs);
        client.DefaultRequestHeaders.UserAgent.ParseAdd("Rabits/1.0 (+recon)");

        using var request = new HttpRequestMessage(HttpMethod.Get, url);
        using var response = await client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cancellationToken);

        var headers = FlattenHeaders(response);
        var tls = capturedCert is not null ? BuildCertInfo(capturedCert, chainValid) : null;
        capturedCert?.Dispose();

        return new WebEndpointInfo
        {
            Url = url,
            StatusCode = (int)response.StatusCode,
            ReasonPhrase = response.ReasonPhrase,
            Server = Get(headers, "Server"),
            PoweredBy = Get(headers, "X-Powered-By"),
            Headers = headers,
            Tls = tls,
            SecurityFindings = SecurityHeaders.Analyze(headers),
        };
    }

    private static Dictionary<string, string> FlattenHeaders(HttpResponseMessage response)
    {
        var headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var header in response.Headers)
            headers[header.Key] = string.Join(", ", header.Value);
        foreach (var header in response.Content.Headers)
            headers[header.Key] = string.Join(", ", header.Value);
        return headers;
    }

    private static TlsCertificateInfo BuildCertInfo(X509Certificate2 cert, bool chainValid)
    {
        var sans = new List<string>();
        try
        {
            var ext = cert.Extensions.FirstOrDefault(e => e.Oid?.Value == "2.5.29.17");
            if (ext is not null)
                sans.AddRange(new X509SubjectAlternativeNameExtension(ext.RawData).EnumerateDnsNames());
        }
        catch
        {
            // SAN parsing is best-effort.
        }

        return new TlsCertificateInfo
        {
            Subject = cert.Subject,
            Issuer = cert.Issuer,
            NotBefore = new DateTimeOffset(cert.NotBefore.ToUniversalTime()),
            NotAfter = new DateTimeOffset(cert.NotAfter.ToUniversalTime()),
            SubjectAltNames = sans,
            ChainValid = chainValid,
        };
    }

    private static string? Get(IReadOnlyDictionary<string, string> headers, string name)
        => headers.TryGetValue(name, out var value) ? value : null;
}
