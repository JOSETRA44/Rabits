using System.Net;
using System.Net.Sockets;
using System.Text;
using Microsoft.Extensions.Logging.Abstractions;
using Rabits.Application.Layer7;
using Rabits.Application.Security;
using Rabits.Infrastructure.Layer7;

namespace Rabits.Tests.Infrastructure;

/// <summary>
/// End-to-end verification of the static secret-hunting path over real HTTP: an in-process server
/// serves an HTML page linking a script that contains a planted AWS key; the handler must find it.
/// </summary>
public sealed class SecretScanIntegrationTests : IDisposable
{
    private const string PlantedKey = "AKIAIOSFODNN7EXAMPLE";

    private readonly HttpListener _listener = new();
    private readonly CancellationTokenSource _cts = new();
    private readonly string _baseUrl;

    public SecretScanIntegrationTests()
    {
        var port = FreePort();
        _baseUrl = $"http://localhost:{port}/";
        _listener.Prefixes.Add(_baseUrl);
        _listener.Start();
        _ = Task.Run(() => ServeAsync(_cts.Token));
    }

    [Fact]
    public async Task Finds_a_planted_secret_in_a_linked_script()
    {
        var clock = new FixedClock(DateTimeOffset.UnixEpoch);
        var audit = new InMemoryAuditLog(clock);
        var scope = new FakeScopePolicy(null);
        var guard = new AuthorizationGuard(scope, clock, audit, NullLogger<AuthorizationGuard>.Instance);
        var handler = new ScanUrlForSecretsHandler(new HttpResourceFetcher(5000), guard, audit);

        var findings = await handler.HandleAsync(new Uri(_baseUrl));

        Assert.Contains(findings, f => f.RuleName == "AWS Access Key ID");
        Assert.DoesNotContain(findings, f => f.RedactedMatch.Contains(PlantedKey)); // redacted
        Assert.Contains(audit.Entries, e => e.OperationName == "web.secrets");
    }

    private async Task ServeAsync(CancellationToken token)
    {
        while (!token.IsCancellationRequested)
        {
            HttpListenerContext context;
            try { context = await _listener.GetContextAsync(); }
            catch { break; }

            var (body, contentType) = context.Request.Url!.AbsolutePath switch
            {
                "/app.js" => ($"var config={{ awsKey: \"{PlantedKey}\" }};", "application/javascript"),
                _ => ("<html><body><script src=\"/app.js\"></script></body></html>", "text/html"),
            };

            context.Response.ContentType = contentType;
            var bytes = Encoding.UTF8.GetBytes(body);
            context.Response.OutputStream.Write(bytes, 0, bytes.Length);
            context.Response.Close();
        }
    }

    private static int FreePort()
    {
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        listener.Stop();
        return port;
    }

    public void Dispose()
    {
        _cts.Cancel();
        try { _listener.Stop(); } catch { }
        _listener.Close();
        _cts.Dispose();
    }
}
