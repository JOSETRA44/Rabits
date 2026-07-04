namespace Rabits.Application.Abstractions;

/// <summary>Identity of the operator running the engine, recorded in the audit trail.</summary>
public interface IOperatorContext
{
    string OperatorName { get; }
}
