namespace Rabits.Application.Abstractions;

/// <summary>Abstracts the current time so authorization and auditing stay testable.</summary>
public interface IClock
{
    DateTimeOffset Now { get; }
}
