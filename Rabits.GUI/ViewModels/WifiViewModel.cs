using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Rabits.Application.Wireless;
using Rabits.Domain.Networking;

namespace Rabits.GUI.ViewModels;

/// <summary>View model for the Wi-Fi reconnaissance view. Owns the observed networks and the scan command.</summary>
public sealed partial class WifiViewModel : ObservableObject
{
    private readonly ScanWirelessNetworksHandler _handler;

    public WifiViewModel(ScanWirelessNetworksHandler handler) => _handler = handler;

    public ObservableCollection<WirelessNetwork> Networks { get; } = new();

    [ObservableProperty]
    private WirelessNetwork? _selectedNetwork;

    [ObservableProperty]
    private bool _isScanning;

    [ObservableProperty]
    private string _statusMessage = "Ready. Press Scan to enumerate nearby networks.";

    [ObservableProperty]
    private bool _hasScanned;

    [RelayCommand(CanExecute = nameof(CanScan))]
    private async Task ScanAsync()
    {
        IsScanning = true;
        StatusMessage = "Scanning…";
        try
        {
            var results = await _handler.HandleAsync();
            Networks.Clear();
            foreach (var n in results)
                Networks.Add(n);

            SelectedNetwork = Networks.FirstOrDefault();
            HasScanned = true;
            StatusMessage = $"{Networks.Count} network(s) observed · {DateTime.Now:HH:mm:ss}";
        }
        catch (Exception ex)
        {
            StatusMessage = $"Scan failed: {ex.Message}";
        }
        finally
        {
            IsScanning = false;
        }
    }

    private bool CanScan() => !IsScanning;

    partial void OnIsScanningChanged(bool value) => ScanCommand.NotifyCanExecuteChanged();
}
