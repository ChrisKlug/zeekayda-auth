using Microsoft.Extensions.Logging;

namespace ZeeKayDa.Auth.AspNetCore.Tests;

/// <summary>
/// Captures every log entry written through it, for the tests that assert what the framework logged —
/// that a refusal was recorded at Error, or that a secret never reached the log.
/// </summary>
/// <remarks>
/// <see cref="Clear"/> exists for a host shared across a test class: the provider is registered once
/// with that host, so each test clears what the previous one left behind.
/// </remarks>
public sealed class CapturingLoggerProvider : ILoggerProvider
{
    private readonly List<(string Category, LogLevel Level, string Message)> _entries = [];

    /// <summary>Everything logged so far.</summary>
    public IReadOnlyList<(string Category, LogLevel Level, string Message)> Entries
    {
        get { lock (_entries) return [.. _entries]; }
    }

    /// <inheritdoc/>
    public ILogger CreateLogger(string categoryName) => new Logger(this, categoryName);

    /// <summary>Discards every captured entry.</summary>
    public void Clear()
    {
        lock (_entries) _entries.Clear();
    }

    /// <inheritdoc/>
    public void Dispose()
    {
    }

    private void Add(string category, LogLevel level, string message)
    {
        lock (_entries) _entries.Add((category, level, message));
    }

    private sealed class Logger(CapturingLoggerProvider owner, string category) : ILogger
    {
        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(
            LogLevel logLevel,
            EventId eventId,
            TState state,
            Exception? exception,
            Func<TState, Exception?, string> formatter) =>
            owner.Add(category, logLevel, formatter(state, exception));
    }
}
