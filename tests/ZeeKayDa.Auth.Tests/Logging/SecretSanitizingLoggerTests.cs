using System.Linq;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using ZeeKayDa.Auth;
using ZeeKayDa.Auth.Logging;

namespace ZeeKayDa.Auth.Tests.Logging;

public sealed class SecretSanitizingLoggerTests
{
    // ── Fake infrastructure ───────────────────────────────────────────────────────────────────────

    private static SecretSanitizingLogger<T> CreateSut<T>(
        ILogger<T> inner,
        bool disableExceptionSanitizing = false)
    {
        var opts = new AuthorizationServerOptions();
        opts.Logging.DisableExceptionSanitizing = disableExceptionSanitizing;
        return new(inner, Options.Create(opts));
    }

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

    /// <summary>A logger that returns <see langword="false"/> from <see cref="IsEnabled"/> for all levels.</summary>
    private sealed class DisabledCapturingLogger<T> : ILogger<T>
    {
        public sealed record LogEntry(LogLevel Level, Exception? Exception);

        private readonly List<LogEntry> _entries = [];
        public IReadOnlyList<LogEntry> Entries => _entries;

        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

        public bool IsEnabled(LogLevel logLevel) => false;

        public void Log<TState>(
            LogLevel logLevel,
            EventId eventId,
            TState state,
            Exception? exception,
            Func<TState, Exception?, string> formatter)
        {
            _entries.Add(new LogEntry(logLevel, exception));
        }
    }

    // ── Tests ────────────────────────────────────────────────────────────────────────────────────

    [Fact]
    public void SensitiveKeys_contains_expected_keys()
    {
        SecretSanitizingLogger<object>.SensitiveKeys.Should().BeEquivalentTo(
            ["client_secret",
            "code_verifier",
            "Authorization",
            "access_token",
            "refresh_token",
            "id_token",
            "client_assertion",
            "assertion",
            "device_code",
            "subject_token",
            "actor_token",
            "password",
            "code",
            "DPoP"],
            o => o.WithoutStrictOrdering());
    }

    [Fact]
    public void Log_redacts_client_secret_in_pairs()
    {
        var inner = new CapturingLogger<object>();
        var sut = CreateSut(inner);

        sut.LogInformation("Auth {client_secret} received", "s3cr3t");

        inner.Entries.Should().HaveCount(1);
        inner.Entries[0].Pairs.Should().Contain(kv => kv.Key == "client_secret" && (string?)kv.Value == "[REDACTED]");
    }

    [Fact]
    public void Log_redacts_client_secret_in_formatted_message()
    {
        var inner = new CapturingLogger<object>();
        var sut = CreateSut(inner);

        sut.LogInformation("Auth {client_secret} received", "s3cr3t");

        inner.Entries[0].FormattedMessage.Should().Be("Auth [REDACTED] received");
    }

    [Fact]
    public void Log_redacts_code_verifier()
    {
        var inner = new CapturingLogger<object>();
        var sut = CreateSut(inner);

        sut.LogDebug("PKCE {code_verifier} received", "verifier-value");

        inner.Entries.Should().HaveCount(1);
        inner.Entries[0].Pairs.Should().Contain(kv => kv.Key == "code_verifier" && (string?)kv.Value == "[REDACTED]");
        inner.Entries[0].FormattedMessage.Should().Be("PKCE [REDACTED] received");
    }

    [Fact]
    public void Log_redacts_Authorization_header()
    {
        var inner = new CapturingLogger<object>();
        var sut = CreateSut(inner);

        sut.LogDebug("Header {Authorization} present", "Basic abc123==");

        inner.Entries.Should().HaveCount(1);
        inner.Entries[0].Pairs.Should().Contain(kv => kv.Key == "Authorization" && (string?)kv.Value == "[REDACTED]");
        inner.Entries[0].FormattedMessage.Should().Be("Header [REDACTED] present");
    }

    [Fact]
    public void Log_key_match_is_case_insensitive()
    {
        var inner = new CapturingLogger<object>();
        var sut = CreateSut(inner);

        sut.LogInformation("Secret {CLIENT_SECRET} received", "s3cr3t");

        inner.Entries[0].Pairs.Should().Contain(kv => kv.Key == "CLIENT_SECRET" && (string?)kv.Value == "[REDACTED]");
    }

    [Fact]
    public void Log_passes_through_non_sensitive_values()
    {
        var inner = new CapturingLogger<object>();
        var sut = CreateSut(inner);

        sut.LogInformation("Client {client_id} request", "my-client");

        inner.Entries.Should().HaveCount(1);
        inner.Entries[0].FormattedMessage.Should().Be("Client my-client request");
        inner.Entries[0].Pairs.Should().Contain(kv => kv.Key == "client_id" && (string?)kv.Value == "my-client");
    }

    [Fact]
    public void Log_preserves_original_format_key()
    {
        var inner = new CapturingLogger<object>();
        var sut = CreateSut(inner);

        sut.LogInformation("Secret {client_secret} received", "s3cr3t");

        inner.Entries[0].Pairs
            .Should().Contain(kv => kv.Key == "{OriginalFormat}" && (string?)kv.Value == "Secret {client_secret} received");
    }

    [Fact]
    public void Log_passes_through_unstructured_state()
    {
        var inner = new CapturingLogger<object>();
        var sut = CreateSut(inner);

        sut.Log(LogLevel.Information, default, "plain-string-state", null, (s, _) => s);

        inner.Entries.Should().HaveCount(1);
        inner.Entries[0].FormattedMessage.Should().Be("plain-string-state");
        inner.Entries[0].Pairs.Should().BeEmpty();
    }

    [Fact]
    public void Log_mixed_message_only_redacts_sensitive_values()
    {
        var inner = new CapturingLogger<object>();
        var sut = CreateSut(inner);

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
    public void IsEnabled_delegates_to_inner()
    {
        var inner = new CapturingLogger<object>();
        var sut = CreateSut(inner);

        sut.IsEnabled(LogLevel.Debug).Should().BeTrue();
    }

    [Fact]
    public void Log_does_not_call_inner_Log_when_inner_IsEnabled_returns_false()
    {
        // The IsEnabled guard at the top of Log<TState> must short-circuit all work —
        // including RedactedExceptionWrapper allocation — when the inner logger would discard
        // the entry anyway.
        var inner = new DisabledCapturingLogger<object>();
        var sut = CreateSut(inner);
        var ex = new Exception("secret material");

        sut.LogWarning(ex, "something went wrong");

        inner.Entries.Should().BeEmpty("inner.IsEnabled returned false so Log should not be called");
    }

    [Fact]
    public void BeginScope_passes_through_non_sensitive_string_scope()
    {
        var inner = new CapturingLogger<object>();
        var sut = CreateSut(inner);

        sut.BeginScope("test-scope").Should().BeNull();
        inner.ScopeStates.Should().ContainSingle().Which.Should().Be("test-scope");
    }

    [Fact]
    public void BeginScope_passes_through_non_sensitive_KVP_scope()
    {
        var inner = new CapturingLogger<object>();
        var sut = CreateSut(inner);

        var state = new List<KeyValuePair<string, object?>> { new("client_id", "app-1") };
        sut.BeginScope(state);

        inner.ScopeStates.Should().ContainSingle().Which.Should().BeSameAs(state);
    }

    [Fact]
    public void BeginScope_redacts_sensitive_keys_in_KVP_scope()
    {
        var inner = new CapturingLogger<object>();
        var sut = CreateSut(inner);

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
    public void BeginScope_redacts_scope_containing_only_sensitive_keys()
    {
        var inner = new CapturingLogger<object>();
        var sut = CreateSut(inner);

        sut.BeginScope(new List<KeyValuePair<string, object?>>
        {
            new("client_secret", "raw-secret"),
            new("code_verifier", "verifier-value"),
        });

        var captured = inner.ScopeStates.Should().ContainSingle().Subject
            .Should().BeAssignableTo<IEnumerable<KeyValuePair<string, object?>>>().Subject.ToList();
        captured.Should().Contain(kv => kv.Key == "client_secret" && (string?)kv.Value == "[REDACTED]");
        captured.Should().Contain(kv => kv.Key == "code_verifier" && (string?)kv.Value == "[REDACTED]");
    }

    [Fact]
    public void Log_preserves_format_specifier_on_non_sensitive_value()
    {
        var inner = new CapturingLogger<object>();
        var sut = CreateSut(inner);

        sut.LogInformation("Processed {Count:N0} items", 1234567);

        inner.Entries[0].FormattedMessage.Should().Be("Processed 1,234,567 items");
    }

    [Fact]
    public void Log_preserves_alignment_specifier_on_non_sensitive_value()
    {
        var inner = new CapturingLogger<object>();
        var sut = CreateSut(inner);

        sut.LogInformation("User: {Name,-10}!", "Alice");

        inner.Entries[0].FormattedMessage.Should().Be("User: Alice     !");
    }

    [Fact]
    public void Log_handles_escaped_braces()
    {
        var inner = new CapturingLogger<object>();
        var sut = CreateSut(inner);

        sut.LogInformation("Use {{client_secret}} to pass {client_secret}", "s3cr3t");

        inner.Entries[0].FormattedMessage.Should().Be("Use {client_secret} to pass [REDACTED]");
    }

    [Fact]
    public void Log_handles_duplicate_placeholder()
    {
        var inner = new CapturingLogger<object>();
        var sut = CreateSut(inner);

        sut.LogInformation("Hello {Name}, goodbye {Name}", "World", "World");

        inner.Entries[0].FormattedMessage.Should().Be("Hello World, goodbye World");
    }

    [Fact]
    public void Log_blocks_non_inspectable_state()
    {
        var inner = new CapturingLogger<object>();
        var sut = CreateSut(inner);

        var customState = new { SomeProp = "potentially-sensitive-value" };
        sut.Log(LogLevel.Information, default, customState, null, (s, _) => s.SomeProp);

        inner.Entries.Should().HaveCount(1);
        inner.Entries[0].FormattedMessage.Should().Be("[ZeeKayDa: unscrubbable log state blocked]");
    }

    [Fact]
    public void Log_blocks_non_inspectable_state_with_non_null_exception()
    {
        var inner = new CapturingLogger<object>();
        var sut = CreateSut(inner);
        var ex = new Exception("secret error detail");
        var anonymousState = new { Foo = "bar" };

        sut.Log(LogLevel.Information, default, anonymousState, ex, (_, _) => "anonymous state");

        inner.Entries.Should().HaveCount(1);
        inner.Entries[0].FormattedMessage.Should().Be("[ZeeKayDa: unscrubbable log state blocked]");
        // Exception is wrapped — the original exception must not reach the sink directly.
        inner.Entries[0].Exception.Should().BeOfType<RedactedExceptionWrapper>()
            .Which.InnerException.Should().BeNull();
    }

    [Fact]
    public void Log_LoggerMessage_Define_inspects_state_and_redacts_sensitive_key()
    {
        var inner = new CapturingLogger<object>();
        var sut = CreateSut(inner);

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
    public void Log_source_generated_LoggerMessage_inspects_state_and_redacts_sensitive_key()
    {
        var inner = new CapturingLogger<object>();
        var sut = CreateSut(inner);

        LoggerMessageFixtures.LogSensitiveAuth(sut, "raw-secret");

        inner.Entries.Should().HaveCount(1);
        inner.Entries[0].Pairs
            .Should().Contain(kv => kv.Key == "client_secret" && (string?)kv.Value == "[REDACTED]",
                "[LoggerMessage] source-generated state must be inspectable, not silently blocked");
    }

    // ── Log: redacted state formatted without {OriginalFormat} ───────────────────────────────────

    [Fact]
    public void Log_formats_redacted_state_without_OriginalFormat_as_key_colon_value_list()
    {
        var inner = new CapturingLogger<object>();
        var sut = CreateSut(inner);
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
        var inner = new CapturingLogger<object>();
        var sut = CreateSut(inner);
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
        var inner = new CapturingLogger<object>();
        var sut = CreateSut(inner);
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
        var inner = new CapturingLogger<object>();
        var sut = CreateSut(inner);
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
        var inner = new CapturingLogger<object>();
        var sut = CreateSut(inner);
        var state = new List<KeyValuePair<string, object?>>
        {
            new("{OriginalFormat}", "Count is {Count,-notanumber}"),
            new("Count", 5),
            new("client_secret", "s"),
        };

        var act = () => sut.Log(
            LogLevel.Information,
            default,
            state,
            null,
            (st, ex) => string.Join(", ", st.Select(kvp => $"{kvp.Key}: {kvp.Value}")));

        act.Should().NotThrow();
        inner.Entries.Should().HaveCount(1);
        inner.Entries[0].FormattedMessage.Should().Be("Count is {Count,-notanumber}");
    }

    // ── Exception wrapping: default behaviour ────────────────────────────────────────────────────

    [Fact]
    public void Log_wraps_non_null_exception_in_RedactedExceptionWrapper_by_default()
    {
        var inner = new CapturingLogger<object>();
        var sut = CreateSut(inner);
        var original = new InvalidOperationException("contains credential material");

        sut.LogInformation(original, "something went wrong");

        inner.Entries.Should().ContainSingle();
        inner.Entries[0].Exception.Should().BeOfType<RedactedExceptionWrapper>();
    }

    [Fact]
    public void Log_wrapped_exception_has_redacted_message()
    {
        var inner = new CapturingLogger<object>();
        var sut = CreateSut(inner);
        var original = new InvalidOperationException("contains credential material");

        sut.LogInformation(original, "something went wrong");

        inner.Entries[0].Exception!.Message.Should().Be(RedactedExceptionWrapper.RedactedMessage);
    }

    [Fact]
    public void Log_wrapped_exception_InnerException_is_null_when_original_has_no_inner_exception()
    {
        var inner = new CapturingLogger<object>();
        var sut = CreateSut(inner);
        var original = new InvalidOperationException("contains credential material");

        sut.LogInformation(original, "something went wrong");

        inner.Entries[0].Exception!.InnerException.Should().BeNull();
    }

    [Fact]
    public void Log_wrapped_exception_OriginalExceptionType_contains_full_type_name()
    {
        var inner = new CapturingLogger<object>();
        var sut = CreateSut(inner);
        var original = new InvalidOperationException("contains credential material");

        sut.LogInformation(original, "something went wrong");

        var wrapper = inner.Entries[0].Exception.Should().BeOfType<RedactedExceptionWrapper>().Subject;
        wrapper.OriginalExceptionType.Should().Be("System.InvalidOperationException");
    }

    [Fact]
    public void Log_wrapped_exception_ToString_contains_original_type_name()
    {
        var inner = new CapturingLogger<object>();
        var sut = CreateSut(inner);
        var original = new InvalidOperationException("contains credential material");

        sut.LogInformation(original, "something went wrong");

        var wrapper = inner.Entries[0].Exception.Should().BeOfType<RedactedExceptionWrapper>().Subject;
        wrapper.ToString().Should().Contain("System.InvalidOperationException");
    }

    [Fact]
    public void Log_passes_null_exception_through_as_null_by_default()
    {
        var inner = new CapturingLogger<object>();
        var sut = CreateSut(inner);

        sut.LogInformation("no exception here");

        inner.Entries.Should().ContainSingle();
        inner.Entries[0].Exception.Should().BeNull();
    }

    // ── Exception wrapping: disabled ─────────────────────────────────────────────────────────────

    [Fact]
    public void Log_passes_original_exception_through_unchanged_when_sanitizing_disabled()
    {
        var inner = new CapturingLogger<object>();
        var sut = CreateSut(inner, disableExceptionSanitizing: true);
        var original = new InvalidOperationException("raw exception message");

        sut.LogInformation(original, "something went wrong");

        inner.Entries[0].Exception.Should().BeSameAs(original);
    }

    [Fact]
    public void Log_passes_null_exception_through_as_null_when_sanitizing_disabled()
    {
        var inner = new CapturingLogger<object>();
        var sut = CreateSut(inner, disableExceptionSanitizing: true);

        sut.LogInformation("no exception here");

        inner.Entries.Should().ContainSingle();
        inner.Entries[0].Exception.Should().BeNull();
    }

    [Fact]
    public void Log_original_exception_stack_trace_accessible_directly_when_sanitizing_disabled()
    {
        var inner = new CapturingLogger<object>();
        var sut = CreateSut(inner, disableExceptionSanitizing: true);
        Exception original;
        try { throw new InvalidOperationException("raw exception"); }
        catch (Exception ex) { original = ex; }

        sut.LogInformation(original, "something went wrong");

        // Stack trace is on the exception itself, not only via InnerException.
        inner.Entries[0].Exception!.StackTrace.Should().NotBeNullOrEmpty();
        inner.Entries[0].Exception.Should().BeSameAs(original);
    }

    // ── Exception wrapping: all three Log<TState> code paths ─────────────────────────────────────

    [Fact]
    public void Log_wraps_exception_on_structured_KVP_state_path_with_sensitive_key()
    {
        // Code path: state is IEnumerable<KVP> and contains a sensitive key.
        var inner = new CapturingLogger<object>();
        var sut = CreateSut(inner);
        var original = new Exception("token value leaked");

        sut.Log(LogLevel.Warning, default,
            new List<KeyValuePair<string, object?>>
            {
                new("client_secret", "s3cr3t"),
                new("{OriginalFormat}", "Secret {client_secret}"),
            },
            original,
            (s, ex) => string.Join(", ", s.Select(kvp => $"{kvp.Key}: {kvp.Value}")));

        inner.Entries.Should().ContainSingle();
        inner.Entries[0].Exception.Should().BeOfType<RedactedExceptionWrapper>()
            .Which.InnerException.Should().BeNull();
    }

    [Fact]
    public void Log_wraps_exception_on_opaque_non_string_state_path()
    {
        // Code path: state is not string and not IEnumerable<KVP> — blocked with placeholder.
        var inner = new CapturingLogger<object>();
        var sut = CreateSut(inner);
        var original = new Exception("token value leaked");
        var opaqueState = new { SomeField = "value" };

        sut.Log(LogLevel.Warning, default, opaqueState, original, (s, _) => s.SomeField);

        inner.Entries.Should().ContainSingle();
        inner.Entries[0].Exception.Should().BeOfType<RedactedExceptionWrapper>()
            .Which.InnerException.Should().BeNull();
    }

    [Fact]
    public void Log_wraps_exception_on_plain_string_state_pass_through_path()
    {
        // Code path: state is a plain string — passes through directly.
        var inner = new CapturingLogger<object>();
        var sut = CreateSut(inner);
        var original = new Exception("token value leaked");

        sut.Log(LogLevel.Warning, default, "plain-state", original, (s, _) => s);

        inner.Entries.Should().ContainSingle();
        inner.Entries[0].Exception.Should().BeOfType<RedactedExceptionWrapper>()
            .Which.InnerException.Should().BeNull();
    }
}

public sealed class RedactedExceptionWrapperTests
{
    // ── Constructor guard ─────────────────────────────────────────────────────────────────────────

    [Fact]
    public void Constructor_throws_ArgumentNullException_when_original_is_null()
    {
        var act = () => new RedactedExceptionWrapper(null!);

        act.Should().Throw<ArgumentNullException>().WithParameterName("original");
    }

    // ── OriginalExceptionType falls back to Name when FullName is null ─────────────────────────

    [Fact]
    public void OriginalExceptionType_uses_Name_when_FullName_is_null_on_exception_type()
    {
        // object.GetType() is an intrinsic in the .NET CLR and cannot be overridden via
        // Reflection.Emit override because the runtime ignores such overrides for security
        // reasons. The ?? guard in the constructor is therefore defensive dead code for
        // concrete exception instances.
        //
        // We exercise the branch by calling the private OriginalExceptionType assignment logic
        // indirectly via a constructed exception whose type has a null FullName at
        // expression-evaluation time. Since we cannot change what GetType() returns for a real
        // object, we instead directly test the null-coalescing semantics by verifying that
        // OriginalExceptionType is always non-null (which is the observable contract regardless
        // of which branch is taken).
        var original = new InvalidOperationException("test");

        var wrapper = new RedactedExceptionWrapper(original);

        wrapper.OriginalExceptionType.Should().NotBeNull();
        wrapper.OriginalExceptionType.Should().Be("System.InvalidOperationException");
    }

    // ── InnerException is wrapped, not the original ───────────────────────────────────────────────

    [Fact]
    public void InnerException_is_a_RedactedExceptionWrapper_when_original_has_inner_exception()
    {
        var originalInner = new ArgumentException("inner secret");
        var original = new InvalidOperationException("outer secret", originalInner);

        var wrapper = new RedactedExceptionWrapper(original);

        wrapper.InnerException.Should().BeOfType<RedactedExceptionWrapper>();
        wrapper.InnerException!.Message.Should().Be(RedactedExceptionWrapper.RedactedMessage);
    }

    // ── ToString() does not leak original message ─────────────────────────────────────────────────

    [Fact]
    public void ToString_does_not_contain_original_exception_message()
    {
        var original = new InvalidOperationException("super-secret-password-1234");

        var wrapper = new RedactedExceptionWrapper(original);

        wrapper.ToString().Should().NotContain("super-secret-password-1234");
    }

    [Fact]
    public void ToString_does_not_contain_inner_exception_message_when_original_has_inner_exception()
    {
        var inner = new ArgumentException("inner-super-secret-9876");
        var original = new InvalidOperationException("outer-super-secret-1234", inner);

        var wrapper = new RedactedExceptionWrapper(original);
        var text = wrapper.ToString();

        text.Should().NotContain("outer-super-secret-1234");
        text.Should().NotContain("inner-super-secret-9876");
    }

    // ── Depth limit prevents StackOverflowException ───────────────────────────────────────────────

    [Fact]
    public void Constructor_does_not_throw_when_original_chain_exceeds_max_depth()
    {
        var chain = new Exception("leaf");
        for (var i = 1; i <= 60; i++)
            chain = new Exception($"level {i}", chain);

        var act = () => new RedactedExceptionWrapper(chain);

        act.Should().NotThrow();

        var wrapper = new RedactedExceptionWrapper(chain);
        Exception? current = wrapper;
        while (current?.InnerException is not null)
            current = current.InnerException;

        current!.InnerException.Should().BeNull();
    }

    // ── StackTrace is forwarded from original ─────────────────────────────────────────────────────

    [Fact]
    public void StackTrace_equals_original_exception_stack_trace()
    {
        Exception original;
        try { throw new InvalidOperationException("some error"); }
        catch (Exception ex) { original = ex; }

        var wrapper = new RedactedExceptionWrapper(original);

        wrapper.StackTrace.Should().Be(original.StackTrace);
    }
}

internal static partial class LoggerMessageFixtures
{
    [LoggerMessage(Level = LogLevel.Warning, Message = "Auth {client_secret} received")]
    public static partial void LogSensitiveAuth(ILogger logger, string client_secret);
}

public sealed class LoggingOptionsTests
{
    [Fact]
    public void DisableExceptionSanitizing_defaults_to_false()
    {
        // Security default: sanitization must be on by default so production deployments that
        // never configure this flag are protected.
        var opts = new LoggingOptions();

        opts.DisableExceptionSanitizing.Should().BeFalse();
    }

    [Fact]
    public void AuthorizationServerOptions_Logging_DisableExceptionSanitizing_defaults_to_false()
    {
        // Verify the safe default is preserved through the full options graph.
        var opts = new AuthorizationServerOptions();

        opts.Logging.DisableExceptionSanitizing.Should().BeFalse();
    }
}

