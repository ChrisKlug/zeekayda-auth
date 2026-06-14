using Microsoft.Extensions.Logging;
using ZeeKayDa.Auth.Logging;

namespace ZeeKayDa.Auth.Tests;

/// <summary>
/// A no-op <see cref="ISanitizingLogger{T}"/> for tests that need a logger instance but do not
/// assert on log output. Equivalent to <see cref="NullLogger{T}"/> but satisfies the
/// <c>ISanitizingLogger&lt;T&gt;</c> constraint.
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
