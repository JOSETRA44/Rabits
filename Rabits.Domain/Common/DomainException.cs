namespace Rabits.Domain.Common;

/// <summary>Base type for all errors that represent a violation of a domain rule.</summary>
public abstract class DomainException : Exception
{
    protected DomainException(string message) : base(message) { }
}
