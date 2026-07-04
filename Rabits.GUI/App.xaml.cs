using System.Windows;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Rabits.GUI.ViewModels;
using Rabits.Infrastructure.DependencyInjection;

namespace Rabits.GUI;

/// <summary>
/// Application entry point. Builds the same Rabits engine the CLI uses via AddRabitsEngine,
/// registers the view models and the shell, then resolves and shows MainWindow.
/// </summary>
public partial class App : System.Windows.Application
{
    private ServiceProvider? _provider;

    protected override void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);

        var services = new ServiceCollection();
        services.AddLogging(builder => builder
            .AddDebug()
            .SetMinimumLevel(LogLevel.Warning));

        services.AddRabitsEngine(options =>
        {
            options.ScopeFilePath = "scope.json";
            options.AuditLogPath = "rabits-audit.jsonl";
        });

        services.AddSingleton<WifiViewModel>();
        services.AddSingleton<MainViewModel>();
        services.AddSingleton<MainWindow>();

        _provider = services.BuildServiceProvider();

        _provider.GetRequiredService<MainWindow>().Show();
    }

    protected override void OnExit(ExitEventArgs e)
    {
        _provider?.Dispose();
        base.OnExit(e);
    }
}
