using Microsoft.Extensions.Logging;
using ZeeKayDa.Auth.Logging;

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

        private readonly List<object> _scopeStates = [];
        public IReadOnlyList<object> ScopeStates => _scopeStates;

        public IDisposable? BeginScope<TState>(TState state) where TState : notnull
        {
            _scopeStates.Add(state);
            return null;
        }

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
                : [];
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
    public void BeginScope_PassesThroughNonSensitiveStringScope()
    {
        var inner = new CapturingLogger<object>();
        var sut = new SecretSanitizingLogger<object>(inner);

        sut.BeginScope("test-scope").Should().BeNull();
        inner.ScopeStates.Should().ContainSingle().Which.Should().Be("test-scope");
    }

    [Fact]
    public void BeginScope_PassesThroughNonSensitiveKVPScope()
    {
        var inner = new CapturingLogger<object>();
        var sut = new SecretSanitizingLogger<object>(inner);

        var state = new List<KeyValuePair<string, object?>> { new("client_id", "app-1") };
        sut.BeginScope(state);

        inner.ScopeStates.Should().ContainSingle().Which.Should().BeSameAs(state);
    }

    [Fact]
    public void BeginScope_RedactsSensitiveKeysInKVPScope()
    {
        var inner = new CapturingLogger<object>();
        var sut = new SecretSanitizingLogger<object>(inner);

        sut.BeginScope(new List<KeyValuePair<string, object?>>
        {
            new("client_id", "app-1"),
            new("client_secret", "raw-secret"),
        });

        var captured = inner.ScopeStates.Should().ContainSingle().Subject
            .Should().BeAssignableTo<IEnumerable<KeyValuePair<string, object?>>>().Subject.ToList();
        captured.Should().Contain(kv => kv.Key == "client_id" && (string?)kv.Value == "app-1");
        captured.Should().Contain(kv => kv.Key == "client_secret" && (string?)kv.Value == "[REDACTED]");
    }

    [Fact]
    public void Log_PreservesFormatSpecifierOnNonSensitiveValue()
    {
        var inner = new CapturingLogger<object>();
        var sut = new SecretSanitizingLogger<object>(inner);

        sut.LogInformation("Processed {Count:N0} items", 1234567);

        inner.Entries[0].FormattedMessage.Should().Be("Processed 1,234,567 items");
    }

    [Fact]
    public void Log_PreservesAlignmentSpecifierOnNonSensitiveValue()
    {
        var inner = new CapturingLogger<object>();
        var sut = new SecretSanitizingLogger<object>(inner);

        sut.LogInformation("User: {Name,-10}!", "Alice");

        inner.Entries[0].FormattedMessage.Should().Be("User: Alice     !");
    }

    [Fact]
    public void Log_HandlesEscapedBraces()
    {
        var inner = new CapturingLogger<object>();
        var sut = new SecretSanitizingLogger<object>(inner);

        sut.LogInformation("Use {{client_secret}} to pass {client_secret}", "s3cr3t");

        inner.Entries[0].FormattedMessage.Should().Be("Use {client_secret} to pass [REDACTED]");
    }

    [Fact]
    public void Log_HandlesDuplicatePlaceholder()
    {
        var inner = new CapturingLogger<object>();
        var sut = new SecretSanitizingLogger<object>(inner);

        sut.LogInformation("Hello {Name}, goodbye {Name}", "World", "World");

        inner.Entries[0].FormattedMessage.Should().Be("Hello World, goodbye World");
    }

    [Fact]
    public void Log_BlocksNonInspectableState()
    {
        var inner = new CapturingLogger<object>();
        var sut = new SecretSanitizingLogger<object>(inner);

        var customState = new { SomeProp = "potentially-sensitive-value" };
        sut.Log(LogLevel.Information, default, customState, null, (s, _) => s.SomeProp);

        inner.Entries.Should().HaveCount(1);
        inner.Entries[0].FormattedMessage.Should().Be("[ZeeKayDa: unscrubbable log state blocked]");
    }

    [Fact]
    public void Log_LoggerMessageDefine_InspectsStateAndRedactsSensitiveKey()
    {
        var inner = new CapturingLogger<object>();
        var sut = new SecretSanitizingLogger<object>(inner);

        var logAction = LoggerMessage.Define<string>(
            LogLevel.Warning,
            new EventId(42),
            "Auth {client_secret} received");

        logAction(sut, "raw-secret", null);

        inner.Entries.Should().HaveCount(1);
        inner.Entries[0].Pairs
            .Should().Contain(kv => kv.Key == "client_secret" && (string?)kv.Value == "[REDACTED]",
                "LoggerMessage.Define state must be inspectable, not silently blocked");
    }

    [Fact]
    public void Log_SourceGeneratedLoggerMessage_InspectsStateAndRedactsSensitiveKey()
    {
        var inner = new CapturingLogger<object>();
        var sut = new SecretSanitizingLogger<object>(inner);

        LoggerMessageFixtures.LogSensitiveAuth(sut, "raw-secret");

        inner.Entries.Should().HaveCount(1);
        inner.Entries[0].Pairs
            .Should().Contain(kv => kv.Key == "client_secret" && (string?)kv.Value == "[REDACTED]",
                "[LoggerMessage] source-generated state must be inspectable, not silently blocked");
    }
}

internal static partial class LoggerMessageFixtures
{
    [LoggerMessage(Level = LogLevel.Warning, Message = "Auth {client_secret} received")]
    public static partial void LogSensitiveAuth(ILogger logger, string client_secret);
}
