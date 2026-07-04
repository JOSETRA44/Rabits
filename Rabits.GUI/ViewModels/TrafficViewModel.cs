using System.Collections.Concurrent;
using System.Collections.ObjectModel;
using System.Windows.Threading;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Rabits.Application.Traffic;
using Rabits.Domain.Traffic;

namespace Rabits.GUI.ViewModels;

/// <summary>
/// View model for the live Traffic view. The capture stream is drained on a background task into a
/// lock-free queue and interlocked counters; a <see cref="DispatcherTimer"/> flushes to the UI in
/// batches every 250 ms. The packet grid is capped at <see cref="MaxRows"/>, so neither the UI
/// thread nor memory is ever overwhelmed by a high packet rate.
/// </summary>
public sealed partial class TrafficViewModel : ObservableObject
{
    private const int MaxRows = 500;
    private const int MaxDrainPerTick = 250;

    private readonly CaptureTrafficHandler _handler;
    private readonly ConcurrentQueue<CapturedPacket> _incoming = new();

    private CancellationTokenSource? _cts;
    private Task? _consumer;
    private TrafficAggregator? _aggregator;
    private DispatcherTimer? _timer;

    public TrafficViewModel(CaptureTrafficHandler handler)
    {
        _handler = handler;
        foreach (var device in handler.ListDevices())
            Devices.Add(device);
        SelectedDevice = Devices.FirstOrDefault();
        IsSimulated = Devices.Count == 1 && Devices[0].Id == "simulated";
    }

    public ObservableCollection<CapturedPacket> Packets { get; } = new();
    public ObservableCollection<CaptureDevice> Devices { get; } = new();

    [ObservableProperty] private CaptureDevice? _selectedDevice;
    [ObservableProperty] private string _filter = string.Empty;
    [ObservableProperty] private bool _isCapturing;
    [ObservableProperty] private bool _isSimulated;
    [ObservableProperty] private string _statusMessage = "Select a device and press Start.";

    [ObservableProperty] private long _totalPackets;
    [ObservableProperty] private long _totalBytes;
    [ObservableProperty] private double _packetsPerSecond;
    [ObservableProperty] private long _tcp;
    [ObservableProperty] private long _udp;
    [ObservableProperty] private long _dns;
    [ObservableProperty] private long _icmp;
    [ObservableProperty] private long _arp;

    [RelayCommand(CanExecute = nameof(CanStart))]
    private void Start()
    {
        Packets.Clear();
        while (_incoming.TryDequeue(out _)) { }
        _aggregator = new TrafficAggregator();
        _cts = new CancellationTokenSource();
        IsCapturing = true;
        StatusMessage = "Capturing…";

        var request = new CaptureRequest
        {
            DeviceId = SelectedDevice?.Id,
            BpfFilter = string.IsNullOrWhiteSpace(Filter) ? null : Filter.Trim(),
        };

        var token = _cts.Token;
        _consumer = Task.Run(async () =>
        {
            try
            {
                await foreach (var packet in _handler.CaptureAsync(request, token))
                {
                    _aggregator!.Add(packet);   // interlocked, never blocks
                    _incoming.Enqueue(packet);  // drained by the UI timer in batches
                }
            }
            catch (OperationCanceledException) { /* stopped */ }
        }, token);

        _timer = new DispatcherTimer { Interval = TimeSpan.FromMilliseconds(250) };
        _timer.Tick += (_, _) => Flush();
        _timer.Start();
    }

    [RelayCommand(CanExecute = nameof(CanStop))]
    private async Task StopAsync()
    {
        _timer?.Stop();
        _cts?.Cancel();
        if (_consumer is not null)
        {
            try { await _consumer; } catch (OperationCanceledException) { }
        }
        Flush();
        IsCapturing = false;
        StatusMessage = $"Stopped · {TotalPackets:N0} packets, {TotalBytes:N0} bytes.";
    }

    private void Flush()
    {
        var drained = 0;
        while (drained < MaxDrainPerTick && _incoming.TryDequeue(out var packet))
        {
            Packets.Insert(0, packet);
            drained++;
        }
        while (Packets.Count > MaxRows)
            Packets.RemoveAt(Packets.Count - 1);

        if (_aggregator is null) return;
        var stats = _aggregator.Snapshot();
        TotalPackets = stats.TotalPackets;
        TotalBytes = stats.TotalBytes;
        PacketsPerSecond = stats.PacketsPerSecond;
        Tcp = stats.CountOf(TrafficProtocol.Tcp);
        Udp = stats.CountOf(TrafficProtocol.Udp);
        Dns = stats.CountOf(TrafficProtocol.Dns);
        Icmp = stats.CountOf(TrafficProtocol.Icmp);
        Arp = stats.CountOf(TrafficProtocol.Arp);
    }

    private bool CanStart() => !IsCapturing;
    private bool CanStop() => IsCapturing;

    partial void OnIsCapturingChanged(bool value)
    {
        StartCommand.NotifyCanExecuteChanged();
        StopCommand.NotifyCanExecuteChanged();
    }
}
