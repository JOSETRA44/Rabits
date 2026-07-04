using System.Collections.Concurrent;
using System.Text;
using System.Text.Json;
using Microsoft.Web.WebView2.Core;
using Rabits.Domain.Layer7;

namespace Rabits.GUI.Layer7;

/// <summary>
/// Bridges WebView2's Chrome DevTools Protocol (Network domain) to the analysis sink. Capture events
/// fire on the UI thread and only do light JSON parsing there; response-body retrieval is async
/// (non-blocking) and the CPU-bound secret scan is offloaded to the thread pool — so interactive
/// browsing is never degraded.
/// </summary>
public sealed class WebView2NetworkBridge
{
    private readonly CoreWebView2 _core;
    private readonly IDynamicAnalysisSink _sink;
    private readonly ConcurrentDictionary<string, PendingRequest> _pending = new();

    public WebView2NetworkBridge(CoreWebView2 core, IDynamicAnalysisSink sink)
    {
        _core = core;
        _sink = sink;
    }

    public async Task StartAsync()
    {
        await _core.CallDevToolsProtocolMethodAsync("Network.enable", "{}");

        _core.GetDevToolsProtocolEventReceiver("Network.requestWillBeSent").DevToolsProtocolEventReceived += OnRequestWillBeSent;
        _core.GetDevToolsProtocolEventReceiver("Network.responseReceived").DevToolsProtocolEventReceived += OnResponseReceived;
        _core.GetDevToolsProtocolEventReceiver("Network.loadingFinished").DevToolsProtocolEventReceived += OnLoadingFinished;
    }

    private void OnRequestWillBeSent(object? sender, CoreWebView2DevToolsProtocolEventReceivedEventArgs e)
    {
        try
        {
            using var doc = JsonDocument.Parse(e.ParameterObjectAsJson);
            var root = doc.RootElement;
            var requestId = root.GetProperty("requestId").GetString()!;
            var request = root.GetProperty("request");
            var method = GetString(request, "method", "GET");
            var url = GetString(request, "url");
            var type = GetString(root, "type", "Other");
            var post = request.TryGetProperty("postData", out var pd) ? Truncate(pd.GetString() ?? "", 200) : string.Empty;
            _pending[requestId] = new PendingRequest(method, url, type, post);
        }
        catch { /* malformed event — skip */ }
    }

    private void OnResponseReceived(object? sender, CoreWebView2DevToolsProtocolEventReceivedEventArgs e)
    {
        try
        {
            using var doc = JsonDocument.Parse(e.ParameterObjectAsJson);
            var root = doc.RootElement;
            var requestId = root.GetProperty("requestId").GetString()!;
            var type = GetString(root, "type", "Other");
            var response = root.GetProperty("response");
            var url = GetString(response, "url");
            var status = response.TryGetProperty("status", out var st) ? st.GetInt32() : 0;
            var mime = GetString(response, "mimeType");
            var size = response.TryGetProperty("encodedDataLength", out var el) && el.TryGetInt64(out var l) ? l : 0;

            var method = _pending.TryGetValue(requestId, out var prev) ? prev.Method : "GET";
            var post = prev?.PostPreview ?? string.Empty;
            _pending[requestId] = new PendingRequest(method, url, type, post) { Mime = mime };

            _sink.ReportExchange(BuildExchange(method, url, status, type, mime, size, post));
        }
        catch { /* malformed event — skip */ }
    }

    private async void OnLoadingFinished(object? sender, CoreWebView2DevToolsProtocolEventReceivedEventArgs e)
    {
        try
        {
            string requestId;
            using (var doc = JsonDocument.Parse(e.ParameterObjectAsJson))
                requestId = doc.RootElement.GetProperty("requestId").GetString() ?? string.Empty;

            if (requestId.Length == 0 || !_pending.TryRemove(requestId, out var pending)) return;
            if (!IsTextLike(pending.Mime)) return;

            // getResponseBody must run on the UI thread; it is async and does not block the UI.
            var json = await _core.CallDevToolsProtocolMethodAsync(
                "Network.getResponseBody", $"{{\"requestId\":\"{requestId}\"}}");

            string body;
            bool base64;
            using (var bodyDoc = JsonDocument.Parse(json))
            {
                var bodyRoot = bodyDoc.RootElement;
                body = GetString(bodyRoot, "body");
                base64 = bodyRoot.TryGetProperty("base64Encoded", out var b64) && b64.GetBoolean();
            }
            if (base64)
            {
                try { body = Encoding.UTF8.GetString(Convert.FromBase64String(body)); }
                catch { return; }
            }

            // Offload the CPU-bound regex/entropy scan to a background thread.
            var findings = await Task.Run(() => SecretHunter.Scan(body, pending.Url));
            foreach (var finding in findings)
                _sink.ReportSecret(finding);
        }
        catch { /* body unavailable or scan failed — non-fatal */ }
    }

    private static HttpExchange BuildExchange(
        string method, string url, int status, string type, string mime, long size, string post)
    {
        var host = url;
        var path = url;
        if (Uri.TryCreate(url, UriKind.Absolute, out var uri))
        {
            host = uri.Host;
            path = uri.AbsolutePath;
        }

        return new HttpExchange
        {
            Method = method,
            Url = url,
            Host = host,
            Path = path,
            StatusCode = status,
            ResourceType = MapType(type),
            MimeType = mime,
            ResponseSize = size,
            RequestBodyPreview = post,
        };
    }

    private static ResourceType MapType(string cdpType) => cdpType switch
    {
        "Document" => ResourceType.Document,
        "Script" => ResourceType.Script,
        "Stylesheet" => ResourceType.Stylesheet,
        "XHR" => ResourceType.Xhr,
        "Fetch" => ResourceType.Fetch,
        "Image" => ResourceType.Image,
        "Font" => ResourceType.Font,
        "WebSocket" => ResourceType.WebSocket,
        "Media" => ResourceType.Media,
        _ => ResourceType.Other,
    };

    private static bool IsTextLike(string mime) =>
        mime.Length == 0
        || mime.StartsWith("text/", StringComparison.OrdinalIgnoreCase)
        || mime.Contains("javascript", StringComparison.OrdinalIgnoreCase)
        || mime.Contains("json", StringComparison.OrdinalIgnoreCase)
        || mime.Contains("html", StringComparison.OrdinalIgnoreCase)
        || mime.Contains("xml", StringComparison.OrdinalIgnoreCase);

    private static string GetString(JsonElement element, string name, string fallback = "")
        => element.TryGetProperty(name, out var value) ? value.GetString() ?? fallback : fallback;

    private static string Truncate(string value, int max) => value.Length <= max ? value : value[..max];

    private sealed record PendingRequest(string Method, string Url, string Type, string PostPreview)
    {
        public string Mime { get; init; } = string.Empty;
    }
}
