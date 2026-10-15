using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using ZeeKayDa.Auth.Logging;

namespace ZeeKayDa.Auth.Tests;

/// <summary>
/// A <see cref="SanitizingLogger{T}"/> that records every entry it lets through, after redaction,
/// so tests can assert on what a service logged.
/// </summary>
internal sealed class CapturingSanitizingLogger<T> : SanitizingLogger<T>
{
    private readonly CapturingLogger _capturing;

    public CapturingSanitizingLogger()
        : this(new CapturingLogger())
    {
    }

    private CapturingSanitizingLogger(CapturingLogger capturing)
        : base(capturing, Options.Create(new AuthorizationServerOptions())) => _capturing = capturing;

    public List<(LogLevel Level, string Message, Exception? Exception)> Entries => _capturing.Entries;

    public IReadOnlyList<string> Warnings =>
        [.. Entries.Where(entry => entry.Level == LogLevel.Warning).Select(entry => entry.Message)];

    private sealed class CapturingLogger : ILogger<T>
    {
        public List<(LogLevel Level, string Message, Exception? Exception)> Entries { get; } = [];

        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;
        public bool IsEnabled(LogLevel logLevel) => true;
        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state,
            Exception? exception, Func<TState, Exception?, string> formatter)
            => Entries.Add((logLevel, formatter(state, exception), exception));
    }
}
