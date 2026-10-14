using Microsoft.Extensions.Logging;

namespace ZeeKayDa.Auth.FileSystem.Tests;

/// <summary>
/// Captures every log call's level and rendered message, so tests can assert on the per-file load
/// lines, the too-soon-NotBefore warning, and the active-key expiry warning without a third-party
/// logging-test package.
/// </summary>
internal sealed class CapturingLogger<T> : ILogger<T>
{
    public List<(LogLevel Level, string Message)> Entries { get; } = [];

    public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;
    public bool IsEnabled(LogLevel logLevel) => true;
    public void Log<TState>(LogLevel logLevel, EventId eventId, TState state,
        Exception? exception, Func<TState, Exception?, string> formatter)
        => Entries.Add((logLevel, formatter(state, exception)));
}
