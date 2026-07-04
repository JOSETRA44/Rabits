using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Rabits.Application.Hosts;
using Rabits.Domain.Engagement;
using Rabits.Domain.Networking;

namespace Rabits.GUI.ViewModels;

/// <summary>View model for the Hosts / Map view: runs a scope-gated discovery sweep and streams results.</summary>
public sealed partial class HostsViewModel : ObservableObject
{
    private readonly DiscoverHostsHandler _handler;

    public HostsViewModel(DiscoverHostsHandler handler) => _handler = handler;

    public ObservableCollection<HostRowViewModel> Hosts { get; } = new();

    public Array Profiles { get; } = Enum.GetValues(typeof(PortScanProfile));

    [ObservableProperty]
    private string _target = "192.168.1.0/24";

    [ObservableProperty]
    private PortScanProfile _selectedProfile = PortScanProfile.Common;

    [ObservableProperty]
    private HostRowViewModel? _selectedHost;

    [ObservableProperty]
    private bool _isScanning;

    [ObservableProperty]
    private string _statusMessage = "Enter a CIDR or IP and press Discover. Active sweeps require an in-scope target.";

    [RelayCommand(CanExecute = nameof(CanDiscover))]
    private async Task DiscoverAsync()
    {
        if (string.IsNullOrWhiteSpace(Target)) return;

        IsScanning = true;
        Hosts.Clear();
        StatusMessage = $"Discovering {Target}…";

        var request = new HostDiscoveryRequest
        {
            Target = Target.Trim(),
            Ports = SelectedProfile,
            ResolveMac = true,
        };

        // Progress fires on the captured UI context, so appending to the bound collection is safe.
        var progress = new Progress<DiscoveredHost>(host => Hosts.Add(new HostRowViewModel(host)));

        try
        {
            var results = await _handler.HandleAsync(request, progress);

            // Replace the streamed set with the final, IP-ordered list.
            Hosts.Clear();
            foreach (var host in results)
                Hosts.Add(new HostRowViewModel(host));

            SelectedHost = Hosts.FirstOrDefault();
            StatusMessage = $"{Hosts.Count} host(s) up in {Target} · {DateTime.Now:HH:mm:ss}";
        }
        catch (OutOfScopeException ex)
        {
            StatusMessage = $"Refused — out of scope: {ex.Message}";
        }
        catch (ArgumentException ex)
        {
            StatusMessage = ex.Message;
        }
        catch (Exception ex)
        {
            StatusMessage = $"Discovery failed: {ex.Message}";
        }
        finally
        {
            IsScanning = false;
        }
    }

    private bool CanDiscover() => !IsScanning;

    partial void OnIsScanningChanged(bool value) => DiscoverCommand.NotifyCanExecuteChanged();
}
