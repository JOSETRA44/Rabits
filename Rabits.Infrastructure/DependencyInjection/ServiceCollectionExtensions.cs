using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Rabits.Application.Abstractions;
using Rabits.Application.Hosts;
using Rabits.Application.Recon;
using Rabits.Application.Security;
using Rabits.Application.Traffic;
using Rabits.Application.Wireless;
using Rabits.Infrastructure.Auditing;
using Rabits.Infrastructure.Engagement;
using Rabits.Infrastructure.Hosts;
using Rabits.Infrastructure.Recon;
using Rabits.Infrastructure.Runtime;
using Rabits.Infrastructure.Traffic;
using Rabits.Infrastructure.Wireless;

namespace Rabits.Infrastructure.DependencyInjection;

/// <summary>
/// Single composition entry point for the Rabits engine. Both the CLI and the GUI call this and
/// get an identical, fully-wired engine — the frontends stay decoupled from each other.
/// </summary>
public static class ServiceCollectionExtensions
{
    public static IServiceCollection AddRabitsEngine(
        this IServiceCollection services, Action<RabitsOptions>? configure = null)
    {
        var options = new RabitsOptions();
        configure?.Invoke(options);
        services.AddSingleton(options);

        // Cross-cutting runtime services.
        services.AddSingleton<IClock, SystemClock>();
        services.AddSingleton<IOperatorContext, EnvironmentOperatorContext>();

        // Engagement scope + tamper-evident audit trail.
        services.AddSingleton<IScopePolicy>(sp =>
            new JsonScopePolicy(options.ScopeFilePath, sp.GetRequiredService<ILogger<JsonScopePolicy>>()));
        services.AddSingleton<IAuditLog>(sp =>
            new FileAuditLog(options.AuditLogPath, sp.GetRequiredService<IClock>()));

        // The hard authorization gate every use case flows through.
        services.AddSingleton<IAuthorizationGuard, AuthorizationGuard>();

        // Capability adapters.
        RegisterWirelessScanner(services, options);
        RegisterHostDiscovery(services, options);
        RegisterWebRecon(services, options);
        RegisterTrafficCapture(services, options);

        // Use cases.
        services.AddTransient<ScanWirelessNetworksHandler>();
        services.AddTransient<DiscoverHostsHandler>();
        services.AddTransient<DnsReconHandler>();
        services.AddTransient<WhoisHandler>();
        services.AddTransient<EnumerateSubdomainsHandler>();
        services.AddTransient<InspectWebEndpointHandler>();
        services.AddSingleton<CaptureTrafficHandler>();

        return services;
    }

    private static void RegisterTrafficCapture(IServiceCollection services, RabitsOptions options)
    {
        if (options.ForceSimulatedCapture || !SharpPcapTrafficCapture.IsAvailable())
        {
            services.AddSingleton<ITrafficCapture, SimulatedTrafficCapture>();
            return;
        }

        services.AddSingleton<ITrafficCapture, SharpPcapTrafficCapture>();
    }

    private static void RegisterWebRecon(IServiceCollection services, RabitsOptions options)
    {
        services.AddSingleton<IDnsResolver>(sp =>
            new DnsUdpClient(sp.GetRequiredService<ILogger<DnsUdpClient>>(), servers: null, options.DnsTimeoutMs));
        services.AddSingleton<IWhoisClient>(sp =>
            new WhoisClient(sp.GetRequiredService<ILogger<WhoisClient>>(), options.WhoisTimeoutMs));
        services.AddSingleton<IWebProbe>(_ => new HttpWebProbe(options.WebProbeTimeoutMs));
        services.AddSingleton<ISubdomainWordlist>(sp =>
            new EmbeddedSubdomainWordlist(options.SubdomainWordlistPath,
                sp.GetRequiredService<ILogger<EmbeddedSubdomainWordlist>>()));
    }

    private static void RegisterHostDiscovery(IServiceCollection services, RabitsOptions options)
    {
        services.AddSingleton<IHostProbe>(_ => new PingHostProbe(options.HostProbeTimeoutMs));
        services.AddSingleton<IReverseDnsResolver, DnsReverseResolver>();
        services.AddSingleton<IPortScanner>(_ =>
            new TcpPortScanner(options.PortConnectTimeoutMs, options.PortScanConcurrency));
        services.AddSingleton<IOuiVendorLookup>(sp =>
            new EmbeddedOuiLookup(options.OuiFilePath, sp.GetRequiredService<ILogger<EmbeddedOuiLookup>>()));

        if (OperatingSystem.IsWindows())
            services.AddSingleton<IArpResolver, SendArpResolver>();
        else
            services.AddSingleton<IArpResolver, NullArpResolver>();
    }

    private static void RegisterWirelessScanner(IServiceCollection services, RabitsOptions options)
    {
        if (options.ForceFakeScanner || !OperatingSystem.IsWindows())
        {
            services.AddSingleton<IWirelessScanner, FakeWirelessScanner>();
            return;
        }

        services.AddSingleton<IWirelessScanner>(sp => new NativeWlanScanner(
            sp.GetRequiredService<ILogger<NativeWlanScanner>>(),
            triggerScan: options.TriggerWifiScan,
            scanSettleDelay: TimeSpan.FromSeconds(options.WifiScanSettleSeconds)));
    }
}
