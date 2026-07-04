using System.Collections.ObjectModel;
using System.Windows.Threading;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Rabits.Application.Abstractions;
using Rabits.Domain.Layer7;
using Rabits.GUI.Layer7;

namespace Rabits.GUI.ViewModels;

/// <summary>
/// View model for the Dynamic Recon view. Implements <see cref="IDynamicAnalysisSink"/> so the
/// WebView2 bridge can push captured exchanges and secrets; all mutations are marshalled to the UI
/// thread and the request grid is capped, so a busy SPA can't overwhelm the UI or memory.
/// </summary>
public sealed partial class DynamicAnalysisViewModel : ObservableObject, IDynamicAnalysisSink
{
    private const int MaxRows = 1000;

    private readonly IScopePolicy _scope;
    private readonly Dispatcher _dispatcher = Dispatcher.CurrentDispatcher;
    private readonly HashSet<string> _apiSeen = new();
    private readonly HashSet<string> _secretSeen = new();

    public DynamicAnalysisViewModel(IScopePolicy scope) => _scope = scope;

    public ObservableCollection<ExchangeRow> Exchanges { get; } = new();
    public ObservableCollection<ApiEndpoint> ApiEndpoints { get; } = new();
    public ObservableCollection<SecretFinding> Secrets { get; } = new();

    [ObservableProperty] private string _url = "https://";
    [ObservableProperty] private int _totalRequests;
    [ObservableProperty] private int _apiCount;
    [ObservableProperty] private int _secretCount;

    /// <summary>Raised by the Navigate command; the view drives the WebView2 control (keeps MVVM clean).</summary>
    public event EventHandler<string>? NavigateRequested;

    [RelayCommand]
    private void Navigate()
    {
        if (TryNormalizeUrl(Url, out var normalized))
        {
            Url = normalized;
            NavigateRequested?.Invoke(this, normalized);
        }
    }

    [RelayCommand]
    private void Clear()
    {
        Exchanges.Clear();
        ApiEndpoints.Clear();
        Secrets.Clear();
        _apiSeen.Clear();
        _secretSeen.Clear();
        TotalRequests = ApiCount = SecretCount = 0;
    }

    public void ReportExchange(HttpExchange exchange) => Marshal(() =>
    {
        var inScope = _scope.Current is null || _scope.Current.Rules.Any(r => r.Matches(exchange.Host));

        Exchanges.Insert(0, new ExchangeRow(exchange, inScope));
        while (Exchanges.Count > MaxRows) Exchanges.RemoveAt(Exchanges.Count - 1);
        TotalRequests++;

        if (exchange.IsApiLike)
        {
            var endpoint = new ApiEndpoint(exchange.Method, exchange.Host, exchange.Path);
            if (_apiSeen.Add(endpoint.Key))
            {
                ApiEndpoints.Insert(0, endpoint);
                ApiCount++;
            }
        }
    });

    public void ReportSecret(SecretFinding finding) => Marshal(() =>
    {
        if (_secretSeen.Add(finding.Key))
        {
            Secrets.Insert(0, finding);
            SecretCount++;
        }
    });

    private void Marshal(Action action)
    {
        if (_dispatcher.CheckAccess()) action();
        else _dispatcher.BeginInvoke(action);
    }

    // Exposed so the view can reflect address-bar changes from in-page navigation.
    public void SetUrlFromBrowser(string url) => Marshal(() => Url = url);

    private static bool TryNormalizeUrl(string url, out string normalized)
    {
        var candidate = url.Contains("://", StringComparison.Ordinal) ? url : $"https://{url}";
        if (Uri.TryCreate(candidate, UriKind.Absolute, out var uri) &&
            (uri.Scheme == Uri.UriSchemeHttp || uri.Scheme == Uri.UriSchemeHttps))
        {
            normalized = uri.ToString();
            return true;
        }
        normalized = url;
        return false;
    }
}
