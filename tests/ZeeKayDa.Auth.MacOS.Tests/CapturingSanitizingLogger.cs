using Microsoft.Extensions.Logging;
using ZeeKayDa.Auth.Logging;

namespace ZeeKayDa.Auth.MacOS.Tests;

/// <summary>
/// Captures every log call's level and rendered message, so tests can assert on the presence and
/// count of the per-item load lines (AC #2), the too-soon-activation warning (AC #7), and the
/// active-item expiry warning, without a third-party logging-test package. Mirrors
/// <c>ZeeKayDa.Auth.Windows.Tests.CapturingSanitizingLogger{T}</c>.
/// </summary>
internal sealed class CapturingSanitizingLogger<T> : ISanitizingLogger<T>
{
    public List<(LogLevel Level, string Message)> Entries { get; } = [];

    public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;
    public bool IsEnabled(LogLevel logLevel) => true;
    public void Log<TState>(LogLevel logLevel, EventId eventId, TState state,
        Exception? exception, Func<TState, Exception?, string> formatter)
        => Entries.Add((logLevel, formatter(state, exception)));
}
