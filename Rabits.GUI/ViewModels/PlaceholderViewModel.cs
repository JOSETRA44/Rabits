namespace Rabits.GUI.ViewModels;

/// <summary>Stand-in content for navigation sections that are on the roadmap but not yet built.</summary>
public sealed class PlaceholderViewModel
{
    public PlaceholderViewModel(string title, string phase)
    {
        Title = title;
        Phase = phase;
    }

    public string Title { get; }
    public string Phase { get; }
    public string Message => $"“{Title}” is planned for {Phase}.";
}
