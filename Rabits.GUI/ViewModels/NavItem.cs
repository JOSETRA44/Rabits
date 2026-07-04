namespace Rabits.GUI.ViewModels;

/// <summary>A single entry in the left navigation rail.</summary>
public sealed class NavItem
{
    public required string Glyph { get; init; }
    public required string Title { get; init; }
    public required object Content { get; init; }
}
