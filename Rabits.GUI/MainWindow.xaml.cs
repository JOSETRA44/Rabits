using System.Windows;
using Rabits.GUI.ViewModels;

namespace Rabits.GUI;

/// <summary>
/// Interaction logic for MainWindow.xaml. The shell is resolved from DI and receives its view model.
/// </summary>
public partial class MainWindow : Window
{
    public MainWindow(MainViewModel viewModel)
    {
        InitializeComponent();
        DataContext = viewModel;
    }
}
