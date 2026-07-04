namespace Rabits.Application.Abstractions;

/// <summary>Supplies candidate subdomain labels for enumeration (embedded set + optional external file).</summary>
public interface ISubdomainWordlist
{
    IReadOnlyList<string> Labels { get; }
}
