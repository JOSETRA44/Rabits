using System.Net;
using System.Net.Sockets;
using System.Text;
using Microsoft.Extensions.Logging.Abstractions;
using Rabits.Application.Auth;
using Rabits.Application.Security;
using Rabits.Domain.Auth;
using Rabits.Domain.Engagement;
using Rabits.Domain.Operations;
using Rabits.Infrastructure.Auth;

namespace Rabits.Tests.Infrastructure;

/// <summary>
/// End-to-end verification of the active credential-audit path against an in-process mock login
/// server — real HTTP over a real socket, but fully local and safe. The mock accepts admin/letmein
/// (302 redirect) and rejects everything else (200 + "Invalid credentials").
/// </summary>
public sealed class HttpAuthProbeIntegrationTests : IDisposable
{
    private readonly HttpListener _listener = new();
    private readonly CancellationTokenSource _cts = new();
    private readonly string _baseUrl;

    public HttpAuthProbeIntegrationTests()
    {
        var port = FreePort();
        _baseUrl = $"http://localhost:{port}/";
        _listener.Prefixes.Add(_baseUrl);
        _listener.Start();
        _ = Task.Run(() => ServeAsync(_cts.Token));
    }

    private Uri LoginUrl => new(_baseUrl + "login");

    [Fact]
    public async Task Probe_accepts_the_valid_credential_and_rejects_others()
    {
        var probe = new HttpAuthProbe(timeoutMs: 5000);
        var target = new AuthTarget
        {
            Protocol = AuthProtocol.HttpForm,
            Url = LoginUrl,
            SuccessStatusCodes = new[] { 302 },
        };

        var good = await probe.TryAsync(target, new Credential("admin", "letmein"));
        var bad = await probe.TryAsync(target, new Credential("admin", "nope"));

        Assert.Equal(AuthResult.Success, good.Result);
        Assert.Equal(302, good.StatusCode);
        Assert.Equal(AuthResult.Failure, bad.Result);
    }

    [Fact]
    public async Task Probe_detects_failure_via_body_marker()
    {
        var probe = new HttpAuthProbe(timeoutMs: 5000);
        var target = new AuthTarget
        {
            Protocol = AuthProtocol.HttpForm,
            Url = LoginUrl,
            FailureBodyContains = "Invalid credentials",
        };

        var bad = await probe.TryAsync(target, new Credential("admin", "nope"));
        Assert.Equal(AuthResult.Failure, bad.Result);
    }

    [Fact]
    public async Task Full_audit_pipeline_finds_the_password_over_real_http()
    {
        var clock = new FixedClock(DateTimeOffset.UnixEpoch);
        var audit = new InMemoryAuditLog(clock);
        var scope = new FakeScopePolicy(new EngagementScope
        {
            Name = "mock-lab",
            Rules = new[] { ScopeRule.Domain("localhost") },
            MaxClassification = OperationClassification.Intrusive,
        });
        var guard = new AuthorizationGuard(scope, clock, audit, NullLogger<AuthorizationGuard>.Instance);
        var handler = new CredentialAuditHandler(new HttpAuthProbe(5000), guard, audit, scope);

        var request = new CredentialAuditRequest
        {
            Target = new AuthTarget { Protocol = AuthProtocol.HttpForm, Url = LoginUrl, SuccessStatusCodes = new[] { 302 } },
            Usernames = new[] { "admin" },
            Passwords = new[] { "123456", "password", "letmein", "qwerty" },
        };

        var summary = await handler.HandleAsync(request);

        Assert.True(summary.AnySuccess);
        Assert.Contains(summary.Successes, c => c.Password == "letmein");
    }

    private async Task ServeAsync(CancellationToken token)
    {
        while (!token.IsCancellationRequested)
        {
            HttpListenerContext context;
            try { context = await _listener.GetContextAsync(); }
            catch { break; }

            using var reader = new StreamReader(context.Request.InputStream, Encoding.UTF8);
            var body = await reader.ReadToEndAsync();
            var form = ParseForm(body);

            if (form.GetValueOrDefault("username") == "admin" && form.GetValueOrDefault("password") == "letmein")
            {
                context.Response.StatusCode = 302;
                context.Response.RedirectLocation = "/dashboard";
            }
            else
            {
                context.Response.StatusCode = 200;
                var bytes = Encoding.UTF8.GetBytes("Invalid credentials");
                context.Response.OutputStream.Write(bytes, 0, bytes.Length);
            }

            context.Response.Close();
        }
    }

    private static Dictionary<string, string> ParseForm(string body)
    {
        var result = new Dictionary<string, string>();
        foreach (var pair in body.Split('&', StringSplitOptions.RemoveEmptyEntries))
        {
            var eq = pair.IndexOf('=');
            if (eq <= 0) continue;
            result[Uri.UnescapeDataString(pair[..eq])] = Uri.UnescapeDataString(pair[(eq + 1)..]);
        }
        return result;
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
