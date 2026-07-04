namespace Rabits.Application.Abstractions;

/// <summary>Supplies a default password list (embedded set + optional external override).</summary>
public interface ICredentialWordlist
{
    IReadOnlyList<string> Passwords { get; }
}
