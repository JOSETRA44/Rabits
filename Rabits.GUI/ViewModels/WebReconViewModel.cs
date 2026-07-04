using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Rabits.Application.Recon;
using Rabits.Domain.Recon;

namespace Rabits.GUI.ViewModels;

/// <summary>View model for the Web Recon view: passive DNS, WHOIS and subdomain enumeration.</summary>
public sealed partial class WebReconViewModel : ObservableObject
{
    private readonly DnsReconHandler _dns;
    private readonly WhoisHandler _whois;
    private readonly EnumerateSubdomainsHandler _subdomains;

    public WebReconViewModel(DnsReconHandler dns, WhoisHandler whois, EnumerateSubdomainsHandler subdomains)
    {
        _dns = dns;
        _whois = whois;
        _subdomains = subdomains;
    }

    public ObservableCollection<DnsRecord> DnsRecords { get; } = new();
    public ObservableCollection<Subdomain> Subdomains { get; } = new();

    [ObservableProperty] private string _domain = "example.com";
    [ObservableProperty] private bool _isRunning;
    [ObservableProperty] private string _statusMessage = "Enter a domain and press Recon (passive: DNS, WHOIS, subdomains).";

    [ObservableProperty] private bool _hasWhois;
    [ObservableProperty] private string _whoisRegistrar = "—";
    [ObservableProperty] private string _whoisCreated = "—";
    [ObservableProperty] private string _whoisExpires = "—";
    [ObservableProperty] private string _whoisNameServers = "—";

    [RelayCommand(CanExecute = nameof(CanRun))]
    private async Task ReconAsync()
    {
        var domain = Domain.Trim().TrimEnd('.');
        if (domain.Length == 0) return;

        IsRunning = true;
        DnsRecords.Clear();
        Subdomains.Clear();
        HasWhois = false;
        StatusMessage = $"Reconnoitring {domain}…";

        try
        {
            foreach (var record in await _dns.HandleAsync(domain))
                DnsRecords.Add(record);

            var whois = await _whois.HandleAsync(domain);
            WhoisRegistrar = whois.Registrar ?? "—";
            WhoisCreated = whois.CreatedOn?.ToString("yyyy-MM-dd") ?? "—";
            WhoisExpires = whois.ExpiresOn is { } e
                ? $"{e:yyyy-MM-dd}" + (whois.DaysUntilExpiry is { } d ? $" ({d} days)" : "")
                : "—";
            WhoisNameServers = whois.NameServers.Count > 0 ? string.Join("\n", whois.NameServers) : "—";
            HasWhois = true;

            var progress = new Progress<Subdomain>(s => Subdomains.Add(s));
            var found = await _subdomains.HandleAsync(domain, progress: progress);
            Subdomains.Clear();
            foreach (var s in found) Subdomains.Add(s);

            StatusMessage = $"{DnsRecords.Count} DNS record(s), {Subdomains.Count} subdomain(s) · {DateTime.Now:HH:mm:ss}";
        }
        catch (Exception ex)
        {
            StatusMessage = $"Recon failed: {ex.Message}";
        }
        finally
        {
            IsRunning = false;
        }
    }

    private bool CanRun() => !IsRunning;

    partial void OnIsRunningChanged(bool value) => ReconCommand.NotifyCanExecuteChanged();
}
