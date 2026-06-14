using Microsoft.Extensions.Logging;
using System.Linq;
using ZeeKayDa.Auth.Logging;

namespace ZeeKayDa.Auth.Tests.Logging;

public sealed class SecretSanitizingLoggerTests
{
    // ── Fake infrastructure ───────────────────────────────────────────────────────────────────────

    private sealed class CapturingInnerLogger<T> : ILogger<T>
    {
        public sealed record LogEntry(string FormattedMessage, Exception? Exception);

        private readonly List<LogEntry> _entries = [];
        public IReadOnlyList<LogEntry> Entries => _entries;

        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;
        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(
            LogLevel logLevel,
            EventId eventId,
            TState state,
            Exception? exception,
            Func<TState, Exception?, string> formatter)
        {
            _entries.Add(new LogEntry(formatter(state, exception), exception));
        }
    }

    // ── Log: blocked non-inspectable state ───────────────────────────────────────────────────────

    [Fact]
    public void Log_blocks_non_inspectable_state_with_non_null_exception()
    {
        var inner = new CapturingInnerLogger<object>();
        var sut = new SecretSanitizingLogger<object>(inner);
        var ex = new Exception("secret error detail");
        var anonymousState = new { Foo = "bar" };

        sut.Log(LogLevel.Information, default, anonymousState, ex, (_, _) => "anonymous state");

        inner.Entries.Should().HaveCount(1);
        inner.Entries[0].FormattedMessage.Should().Be("[ZeeKayDa: unscrubbable log state blocked]");
        inner.Entries[0].Exception.Should().BeSameAs(ex);
    }

    // ── Log: redacted state formatted without {OriginalFormat} ───────────────────────────────────

    [Fact]
    public void Log_formats_redacted_state_without_OriginalFormat_as_key_colon_value_list()
    {
        var inner = new CapturingInnerLogger<object>();
        var sut = new SecretSanitizingLogger<object>(inner);
        var state = new List<KeyValuePair<string, object?>>
        {
            new("client_secret", "mysecret"),
        };

        sut.Log(LogLevel.Information, default, state, null, (s, ex) => string.Join(", ", s.Select(kvp => $"{kvp.Key}: {kvp.Value}")));

        inner.Entries.Should().HaveCount(1);
        inner.Entries[0].FormattedMessage.Should().Be("client_secret: [REDACTED]");
    }

    // ── Log: FormatTemplate edge cases ───────────────────────────────────────────────────────────

    [Fact]
    public void Log_handles_unclosed_brace_in_template_without_throwing()
    {
        var inner = new CapturingInnerLogger<object>();
        var sut = new SecretSanitizingLogger<object>(inner);
        var state = new List<KeyValuePair<string, object?>>
        {
            new("client_secret", "s"),
            new("{OriginalFormat}", "x={Unclosed"),
        };

        var act = () => sut.Log(LogLevel.Information, default, state, null, (st, ex) => string.Join(", ", st.Select(kvp => $"{kvp.Key}: {kvp.Value}")));

        act.Should().NotThrow();
        inner.Entries.Should().HaveCount(1);
        inner.Entries[0].FormattedMessage.Should().NotBeNull();
    }

    [Fact]
    public void Log_handles_missing_value_for_placeholder_without_throwing()
    {
        var inner = new CapturingInnerLogger<object>();
        var sut = new SecretSanitizingLogger<object>(inner);
        var state = new List<KeyValuePair<string, object?>>
        {
            new("client_secret", "s"),
            new("{OriginalFormat}", "Count is {Count}"),
        };

        var act = () => sut.Log(LogLevel.Information, default, state, null, (st, ex) => string.Join(", ", st.Select(kvp => $"{kvp.Key}: {kvp.Value}")));

        act.Should().NotThrow();
        inner.Entries.Should().HaveCount(1);
        inner.Entries[0].FormattedMessage.Should().NotBeNull();
    }

    // ── Log: RedactedLogValues.ToString() fallback — non-string {OriginalFormat} ─────────────────

    [Fact]
    public void Log_formats_redacted_state_with_non_string_OriginalFormat_as_key_colon_value_list()
    {
        var inner = new CapturingInnerLogger<object>();
        var sut = new SecretSanitizingLogger<object>(inner);
        var state = new List<KeyValuePair<string, object?>>
        {
            new("{OriginalFormat}", 42),
            new("safe_key", "safe_value"),
            new("client_secret", "topsecret"),
        };

        sut.Log(LogLevel.Information, default, state, null, (s, ex) => s.ToString()!);

        inner.Entries.Should().HaveCount(1);
        inner.Entries[0].FormattedMessage.Should().Be("{OriginalFormat}: 42, safe_key: safe_value, client_secret: [REDACTED]");
    }

    // ── Log: FormatTemplate catch block — raw template returned when string.Format throws ────────

    [Fact]
    public void Log_returns_raw_template_when_string_Format_throws_in_FormatTemplate()
    {
        var inner = new CapturingInnerLogger<object>();
        var sut = new SecretSanitizingLogger<object>(inner);
        var state = new List<KeyValuePair<string, object?>>
        {
            new("{OriginalFormat}", "Count is {Count,-notanumber}"),
            new("Count", 5),
            new("client_secret", "s"),
        };

        var act = () => sut.Log(LogLevel.Information, default, state, null, (st, ex) => st.ToString()!);

        act.Should().NotThrow();
        inner.Entries.Should().HaveCount(1);
        inner.Entries[0].FormattedMessage.Should().Be("Count is {Count,-notanumber}");
    }
}
