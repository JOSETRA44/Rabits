using Rabits.Application.Abstractions;

namespace Rabits.Infrastructure.Runtime;

public sealed class SystemClock : IClock
{
    public DateTimeOffset Now => DateTimeOffset.Now;
}
