using Rabits.Domain.Recon;

namespace Rabits.Application.Abstractions;

/// <summary>Inspects a web endpoint (HTTP response + TLS certificate). Active — connects to the target.</summary>
public interface IWebProbe
{
    Task<WebEndpointInfo> InspectAsync(Uri url, CancellationToken cancellationToken = default);
}
