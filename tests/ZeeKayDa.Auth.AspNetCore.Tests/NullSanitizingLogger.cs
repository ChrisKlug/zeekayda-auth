using Microsoft.Extensions.Logging;
using ZeeKayDa.Auth.Logging;

namespace ZeeKayDa.Auth.AspNetCore.Tests;

/// <summary>
/// A no-op <see cref="ISanitizingLogger{T}"/> for tests that need a logger instance but do not
/// assert on log output.
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
