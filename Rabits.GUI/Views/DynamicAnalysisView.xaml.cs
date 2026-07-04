using System.Diagnostics;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using Rabits.GUI.Layer7;
using Rabits.GUI.ViewModels;

namespace Rabits.GUI.Views;

/// <summary>
/// Code-behind is deliberately thin: it owns the WebView2 control lifecycle and wires it to the
/// view model (which holds all state). No analysis logic lives here.
/// </summary>
public partial class DynamicAnalysisView : UserControl
{
    private WebView2NetworkBridge? _bridge;
    private bool _initialized;

    public DynamicAnalysisView() => InitializeComponent();

    private async void OnLoaded(object sender, RoutedEventArgs e)
    {
        if (_initialized || DataContext is not DynamicAnalysisViewModel vm) return;
        _initialized = true;

        vm.NavigateRequested += (_, url) => Navigate(url);

        try
        {
            await Browser.EnsureCoreWebView2Async();

            _bridge = new WebView2NetworkBridge(Browser.CoreWebView2, vm);
            await _bridge.StartAsync();

            Browser.CoreWebView2.SourceChanged += (_, _) => vm.SetUrlFromBrowser(Browser.Source?.ToString() ?? string.Empty);
            Browser.CoreWebView2.Navigate("https://example.com/");
        }
        catch (Exception ex)
        {
            // WebView2 Runtime missing or failed to start — surface in the address bar, don't crash.
            Debug.WriteLine($"WebView2 init failed: {ex.Message}");
            vm.SetUrlFromBrowser("WebView2 Runtime not available — install the Evergreen Runtime.");
        }
    }

    private void Navigate(string url)
    {
        try
        {
            if (Browser.CoreWebView2 is not null && Uri.TryCreate(url, UriKind.Absolute, out _))
                Browser.CoreWebView2.Navigate(url);
        }
        catch (Exception ex)
        {
            Debug.WriteLine($"Navigate failed: {ex.Message}");
        }
    }

    private void OnAddressKeyDown(object sender, KeyEventArgs e)
    {
        if (e.Key == Key.Enter && DataContext is DynamicAnalysisViewModel vm && vm.NavigateCommand.CanExecute(null))
            vm.NavigateCommand.Execute(null);
    }
}
