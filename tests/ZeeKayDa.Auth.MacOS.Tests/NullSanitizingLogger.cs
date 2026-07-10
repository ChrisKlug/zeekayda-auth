using Microsoft.Extensions.Logging;
using ZeeKayDa.Auth.Logging;

namespace ZeeKayDa.Auth.MacOS.Tests;

/// <summary>
/// A no-op <see cref="ISanitizingLogger{T}"/> for tests that need a logger instance but do not assert
/// on log output. Duplicated per test assembly since internal types are not visible across test
/// assemblies — mirrors <c>ZeeKayDa.Auth.Windows.Tests.NullSanitizingLogger{T}</c>.
/// </summary>
internal sealed class NullSanitizingLogger<T> : ISanitizingLogger<T>
{
    public static readonly NullSanitizingLogger<T> Instance = new();

    public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;
    public bool IsEnabled(LogLevel logLevel) => false;
    public void Log<TState>(LogLevel logLevel, EventId eventId, TState state,
        Exception? exception, Func<TState, Exception?, string> formatter)
    { }
}
