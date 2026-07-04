using Rabits.Application.Abstractions;

namespace Rabits.Infrastructure.Runtime;

/// <summary>Derives the operator identity from the current OS user and machine.</summary>
public sealed class EnvironmentOperatorContext : IOperatorContext
{
    public string OperatorName { get; } = $"{Environment.UserName}@{Environment.MachineName}";
}
