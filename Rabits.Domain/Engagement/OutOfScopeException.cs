using Rabits.Domain.Common;
using Rabits.Domain.Operations;

namespace Rabits.Domain.Engagement;

/// <summary>
/// Raised when an active operation is attempted against a target that the current engagement
/// scope does not authorize. The engine must not perform the operation when this is thrown.
/// </summary>
public sealed class OutOfScopeException : DomainException
{
    public RabitsOperation Operation { get; }

    public OutOfScopeException(RabitsOperation operation, string reason)
        : base($"Operation '{operation.Name}' against '{operation.Target}' denied: {reason}.")
    {
        Operation = operation;
    }
}
