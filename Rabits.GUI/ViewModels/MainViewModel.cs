using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;
using Rabits.Application.Abstractions;

namespace Rabits.GUI.ViewModels;

/// <summary>Shell view model: owns the navigation rail, the active content, and the scope indicator.</summary>
public sealed partial class MainViewModel : ObservableObject
{
    public MainViewModel(WifiViewModel wifi, HostsViewModel hosts, WebReconViewModel web, TrafficViewModel traffic,
        IScopePolicy scope, IOperatorContext operatorContext)
    {
        OperatorName = operatorContext.OperatorName;

        var current = scope.Current;
        if (current is null)
        {
            ScopeStatus = "No engagement scope — active ops disabled";
            ScopeInScope = false;
        }
        else
        {
            ScopeStatus = $"Scope: {current.Name}";
            ScopeInScope = true;
        }

        NavItems = new ObservableCollection<NavItem>
        {
            new() { Glyph = "📶", Title = "Wi-Fi", Content = wifi },
            new() { Glyph = "🖥", Title = "Hosts / Map", Content = hosts },
            new() { Glyph = "🌊", Title = "Traffic", Content = traffic },
            new() { Glyph = "🌐", Title = "Web Recon", Content = web },
            new() { Glyph = "🎯", Title = "Attacks", Content = new PlaceholderViewModel("Attacks", "Phase 5") },
            new() { Glyph = "📄", Title = "Reports", Content = new PlaceholderViewModel("Reports", "cross-cutting") },
        };

        SelectedNav = NavItems[0];
    }

    public ObservableCollection<NavItem> NavItems { get; }

    [ObservableProperty]
    private NavItem? _selectedNav;

    [ObservableProperty]
    private object? _currentContent;

    [ObservableProperty]
    private string _scopeStatus = string.Empty;

    [ObservableProperty]
    private bool _scopeInScope;

    [ObservableProperty]
    private string _operatorName = string.Empty;

    partial void OnSelectedNavChanged(NavItem? value) => CurrentContent = value?.Content;
}
