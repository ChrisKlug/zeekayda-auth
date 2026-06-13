using Microsoft.Extensions.Logging;
using ZeeKayDa.Auth.AspNetCore.Logging;

namespace ZeeKayDa.Auth.AspNetCore.Tests.Logging;

public sealed class SecretSanitizingLoggerTests
{
    // ── Fake infrastructure ───────────────────────────────────────────────────────────────────────

    private sealed class CapturingLogger<T> : ILogger<T>
    {
        public sealed record LogEntry(
            LogLevel Level,
            string FormattedMessage,
            IReadOnlyList<KeyValuePair<string, object?>> Pairs,
            Exception? Exception);

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
            var pairs = state is IEnumerable<KeyValuePair<string, object?>> enumerable
                ? enumerable.ToList()
                : (IReadOnlyList<KeyValuePair<string, object?>>)[];
            _entries.Add(new LogEntry(logLevel, formatter(state, exception), pairs, exception));
        }
    }

    // ── Tests ────────────────────────────────────────────────────────────────────────────────────

    [Fact]
    public void SensitiveKeys_ContainsExpectedKeys()
    {
        SecretSanitizingLogger<object>.SensitiveKeys.Should().BeEquivalentTo(
            ["client_secret", "code_verifier", "Authorization"],
            o => o.WithoutStrictOrdering());
    }

    [Fact]
    public void Log_RedactsClientSecretInPairs()
    {
        var inner = new CapturingLogger<object>();
        var sut = new SecretSanitizingLogger<object>(inner);

        sut.LogInformation("Auth {client_secret} received", "s3cr3t");

        inner.Entries.Should().HaveCount(1);
        inner.Entries[0].Pairs.Should().Contain(kv => kv.Key == "client_secret" && (string?)kv.Value == "[REDACTED]");
    }

    [Fact]
    public void Log_RedactsClientSecretInFormattedMessage()
    {
        var inner = new CapturingLogger<object>();
        var sut = new SecretSanitizingLogger<object>(inner);

        sut.LogInformation("Auth {client_secret} received", "s3cr3t");

        inner.Entries[0].FormattedMessage.Should().Be("Auth [REDACTED] received");
    }

    [Fact]
    public void Log_RedactsCodeVerifier()
    {
        var inner = new CapturingLogger<object>();
        var sut = new SecretSanitizingLogger<object>(inner);

        sut.LogDebug("PKCE {code_verifier} received", "verifier-value");

        inner.Entries.Should().HaveCount(1);
        inner.Entries[0].Pairs.Should().Contain(kv => kv.Key == "code_verifier" && (string?)kv.Value == "[REDACTED]");
        inner.Entries[0].FormattedMessage.Should().Be("PKCE [REDACTED] received");
    }

    [Fact]
    public void Log_RedactsAuthorizationHeader()
    {
        var inner = new CapturingLogger<object>();
        var sut = new SecretSanitizingLogger<object>(inner);

        sut.LogDebug("Header {Authorization} present", "Basic abc123==");

        inner.Entries.Should().HaveCount(1);
        inner.Entries[0].Pairs.Should().Contain(kv => kv.Key == "Authorization" && (string?)kv.Value == "[REDACTED]");
        inner.Entries[0].FormattedMessage.Should().Be("Header [REDACTED] present");
    }

    [Fact]
    public void Log_KeyMatchIsCaseInsensitive()
    {
        var inner = new CapturingLogger<object>();
        var sut = new SecretSanitizingLogger<object>(inner);

        sut.LogInformation("Secret {CLIENT_SECRET} received", "s3cr3t");

        inner.Entries[0].Pairs.Should().Contain(kv => kv.Key == "CLIENT_SECRET" && (string?)kv.Value == "[REDACTED]");
    }

    [Fact]
    public void Log_PassesThroughNonSensitiveValues()
    {
        var inner = new CapturingLogger<object>();
        var sut = new SecretSanitizingLogger<object>(inner);

        sut.LogInformation("Client {client_id} request", "my-client");

        inner.Entries.Should().HaveCount(1);
        inner.Entries[0].FormattedMessage.Should().Be("Client my-client request");
        inner.Entries[0].Pairs.Should().Contain(kv => kv.Key == "client_id" && (string?)kv.Value == "my-client");
    }

    [Fact]
    public void Log_PreservesOriginalFormatKey()
    {
        var inner = new CapturingLogger<object>();
        var sut = new SecretSanitizingLogger<object>(inner);

        sut.LogInformation("Secret {client_secret} received", "s3cr3t");

        inner.Entries[0].Pairs
            .Should().Contain(kv => kv.Key == "{OriginalFormat}" && (string?)kv.Value == "Secret {client_secret} received");
    }

    [Fact]
    public void Log_PassesThroughUnstructuredState()
    {
        var inner = new CapturingLogger<object>();
        var sut = new SecretSanitizingLogger<object>(inner);

        sut.Log(LogLevel.Information, default, "plain-string-state", null, (s, _) => s);

        inner.Entries.Should().HaveCount(1);
        inner.Entries[0].FormattedMessage.Should().Be("plain-string-state");
        inner.Entries[0].Pairs.Should().BeEmpty();
    }

    [Fact]
    public void Log_MixedMessage_OnlyRedactsSensitiveValues()
    {
        var inner = new CapturingLogger<object>();
        var sut = new SecretSanitizingLogger<object>(inner);

        sut.LogWarning("Client {client_id} used {client_secret} via {grant_type}",
            "my-client", "s3cr3t", "authorization_code");

        inner.Entries.Should().HaveCount(1);
        inner.Entries[0].FormattedMessage.Should().Be("Client my-client used [REDACTED] via authorization_code");
        inner.Entries[0].Pairs.Should()
            .Contain(kv => kv.Key == "client_id" && (string?)kv.Value == "my-client").And
            .Contain(kv => kv.Key == "client_secret" && (string?)kv.Value == "[REDACTED]").And
            .Contain(kv => kv.Key == "grant_type" && (string?)kv.Value == "authorization_code");
    }

    [Fact]
    public void IsEnabled_DelegatesToInner()
    {
        var inner = new CapturingLogger<object>();
        var sut = new SecretSanitizingLogger<object>(inner);

        sut.IsEnabled(LogLevel.Debug).Should().BeTrue();
    }

    [Fact]
    public void BeginScope_DelegatesToInner()
    {
        var inner = new CapturingLogger<object>();
        var sut = new SecretSanitizingLogger<object>(inner);

        sut.BeginScope("test-scope").Should().BeNull();
    }
}
