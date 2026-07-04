using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Rabits.Application.Abstractions;
using Rabits.Application.Security;
using Rabits.Application.Wireless;
using Rabits.Infrastructure.Auditing;
using Rabits.Infrastructure.Engagement;
using Rabits.Infrastructure.Runtime;
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

        // Use cases.
        services.AddTransient<ScanWirelessNetworksHandler>();

        return services;
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
