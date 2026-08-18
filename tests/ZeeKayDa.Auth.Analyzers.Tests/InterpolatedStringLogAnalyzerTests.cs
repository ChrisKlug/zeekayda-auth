using System.Collections.Immutable;
using System.Linq;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.Diagnostics;
using ZeeKayDa.Auth.Analyzers;

namespace ZeeKayDa.Auth.Analyzers.Tests;

public sealed class InterpolatedStringLogAnalyzerTests
{
    // ── Diagnostic fires ──────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task Diagnostic_fires_on_interpolated_string_message_template()
    {
        var source = """
            using Microsoft.Extensions.Logging;
            namespace ZeeKayDa.Auth.Logging
            {
                internal interface ISanitizingLogger<T> : ILogger<T> { }
            }
            namespace ZeeKayDa.Auth.Services
            {
                using ZeeKayDa.Auth.Logging;
                class MyService
                {
                    void DoWork()
                    {
                        ISanitizingLogger<object> logger = null!;
                        string value = "x";
                        logger.LogInformation($"client_secret={value}");
                    }
                }
            }
            """;

        var diagnostics = await GetDiagnosticsAsync(source);

        diagnostics.Should().ContainSingle()
            .Which.Id.Should().Be(InterpolatedStringLogAnalyzer.DiagnosticId);
    }

    [Fact]
    public async Task Diagnostic_fires_on_string_concatenation_with_variable()
    {
        var source = """
            using Microsoft.Extensions.Logging;
            namespace ZeeKayDa.Auth.Logging
            {
                internal interface ISanitizingLogger<T> : ILogger<T> { }
            }
            namespace ZeeKayDa.Auth.Services
            {
                using ZeeKayDa.Auth.Logging;
                class MyService
                {
                    void DoWork()
                    {
                        ISanitizingLogger<object> logger = null!;
                        string value = "x";
                        logger.LogInformation("client_secret=" + value);
                    }
                }
            }
            """;

        var diagnostics = await GetDiagnosticsAsync(source);

        diagnostics.Should().ContainSingle()
            .Which.Id.Should().Be(InterpolatedStringLogAnalyzer.DiagnosticId);
    }

    [Fact]
    public async Task Diagnostic_fires_on_computed_message_template()
    {
        var source = """
            using Microsoft.Extensions.Logging;
            namespace ZeeKayDa.Auth.Logging
            {
                internal interface ISanitizingLogger<T> : ILogger<T> { }
            }
            namespace ZeeKayDa.Auth.Services
            {
                using ZeeKayDa.Auth.Logging;
                class MyService
                {
                    void DoWork()
                    {
                        ISanitizingLogger<object> logger = null!;
                        var msg = "hello";
                        logger.LogInformation(msg);
                    }
                }
            }
            """;

        var diagnostics = await GetDiagnosticsAsync(source);

        diagnostics.Should().ContainSingle()
            .Which.Id.Should().Be(InterpolatedStringLogAnalyzer.DiagnosticId);
    }

    [Fact]
    public async Task Diagnostic_fires_on_aliased_sensitive_variable()
    {
        var source = """
            using Microsoft.Extensions.Logging;
            namespace ZeeKayDa.Auth.Logging
            {
                internal interface ISanitizingLogger<T> : ILogger<T> { }
            }
            namespace ZeeKayDa.Auth.Services
            {
                using ZeeKayDa.Auth.Logging;
                class MyService
                {
                    void DoWork()
                    {
                        ISanitizingLogger<object> logger = null!;
                        string clientSecret = "x";
                        var v = clientSecret;
                        logger.LogInformation($"creds={v}");
                    }
                }
            }
            """;

        var diagnostics = await GetDiagnosticsAsync(source);

        diagnostics.Should().ContainSingle()
            .Which.Id.Should().Be(InterpolatedStringLogAnalyzer.DiagnosticId);
    }

    [Fact]
    public async Task Diagnostic_fires_on_LogWarning_method()
    {
        var source = """
            using Microsoft.Extensions.Logging;
            namespace ZeeKayDa.Auth.Logging
            {
                internal interface ISanitizingLogger<T> : ILogger<T> { }
            }
            namespace ZeeKayDa.Auth.Services
            {
                using ZeeKayDa.Auth.Logging;
                class MyService
                {
                    void DoWork()
                    {
                        ISanitizingLogger<object> logger = null!;
                        string value = "x";
                        logger.LogWarning($"secret={value}");
                    }
                }
            }
            """;

        var diagnostics = await GetDiagnosticsAsync(source);

        diagnostics.Should().ContainSingle()
            .Which.Id.Should().Be(InterpolatedStringLogAnalyzer.DiagnosticId);
    }

    [Fact]
    public async Task Diagnostic_fires_on_second_string_argument()
    {
        var source = """
            using System;
            using Microsoft.Extensions.Logging;
            namespace ZeeKayDa.Auth.Logging
            {
                internal interface ISanitizingLogger<T> : ILogger<T> { }
            }
            namespace ZeeKayDa.Auth.Services
            {
                using ZeeKayDa.Auth.Logging;
                class MyService
                {
                    void DoWork()
                    {
                        ISanitizingLogger<object> logger = null!;
                        Exception ex = null!;
                        string v = "x";
                        logger.LogError(ex, $"value={v}");
                    }
                }
            }
            """;

        var diagnostics = await GetDiagnosticsAsync(source);

        diagnostics.Should().ContainSingle()
            .Which.Id.Should().Be(InterpolatedStringLogAnalyzer.DiagnosticId);
    }

    [Fact]
    public async Task Diagnostic_fires_on_string_format_message_template()
    {
        var source = """
            using Microsoft.Extensions.Logging;
            namespace ZeeKayDa.Auth.Logging
            {
                internal interface ISanitizingLogger<T> : ILogger<T> { }
            }
            namespace ZeeKayDa.Auth.Services
            {
                using ZeeKayDa.Auth.Logging;
                class MyService
                {
                    void DoWork()
                    {
                        ISanitizingLogger<object> logger = null!;
                        string someValue = "x";
                        logger.LogInformation(string.Format("val={0}", someValue));
                    }
                }
            }
            """;

        var diagnostics = await GetDiagnosticsAsync(source);

        diagnostics.Should().ContainSingle()
            .Which.Id.Should().Be(InterpolatedStringLogAnalyzer.DiagnosticId);
    }

    [Fact]
    public async Task Diagnostic_still_fires_inside_class_implementing_only_ILogger()
    {
        // A class that implements ILogger<T> but NOT ISanitizingLogger<T> must NOT be exempt.
        var source = """
            using System;
            using Microsoft.Extensions.Logging;
            namespace ZeeKayDa.Auth.Services
            {
                internal sealed class EvilService : ILogger<EvilService>
                {
                    private readonly ILogger<EvilService> _logger;
                    public EvilService(ILogger<EvilService> logger) { _logger = logger; }
                    public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;
                    public bool IsEnabled(LogLevel level) => false;
                    public void Log<TState>(LogLevel level, EventId id, TState state, Exception? ex, Func<TState, Exception?, string> f) { }
                    public void DoSomething()
                    {
                        string secret = "s3cr3t";
                        _logger.LogInformation($"secret={secret}");
                    }
                }
            }
            """;

        var diagnostics = await GetDiagnosticsAsync(source);

        diagnostics.Should().ContainSingle()
            .Which.Id.Should().Be(InterpolatedStringLogAnalyzer.DiagnosticId);
    }

    [Fact]
    public async Task No_exemption_for_non_generic_ISanitizingLogger()
    {
        // A non-generic ISanitizingLogger in the same namespace must NOT grant the exemption —
        // only the genuine generic ISanitizingLogger<T> (TypeParameters.Length == 1) is trusted.
        var source = """
            using Microsoft.Extensions.Logging;
            namespace ZeeKayDa.Auth.Logging
            {
                internal interface ISanitizingLogger { }
            }
            namespace ZeeKayDa.Auth.Services
            {
                using ZeeKayDa.Auth.Logging;
                internal sealed class FakeService : ISanitizingLogger
                {
                    void DoWork()
                    {
                        ILogger<object> logger = null!;
                        string value = "x";
                        logger.LogInformation($"val={value}");
                    }
                }
            }
            """;

        var diagnostics = await GetDiagnosticsAsync(source);

        diagnostics.Should().ContainSingle()
            .Which.Id.Should().Be(InterpolatedStringLogAnalyzer.DiagnosticId);
    }

    [Fact]
    public async Task No_exemption_for_type_that_implements_neither_ILogger_nor_ISanitizingLogger()
    {
        // Documents the exemption boundary: a plain class that implements neither ILogger<T>
        // nor ISanitizingLogger<T> must still trigger the diagnostic when it calls Log*.
        var source = """
            using Microsoft.Extensions.Logging;
            namespace ZeeKayDa.Auth.Services
            {
                class PlainService
                {
                    void DoWork()
                    {
                        ILogger<object> logger = null!;
                        string value = "x";
                        logger.LogInformation($"val={value}");
                    }
                }
            }
            """;

        var diagnostics = await GetDiagnosticsAsync(source);

        diagnostics.Should().ContainSingle()
            .Which.Id.Should().Be(InterpolatedStringLogAnalyzer.DiagnosticId);
    }

    [Fact]
    public async Task Diagnostic_fires_inside_friend_assembly_class_implementing_ISanitizingLogger()
    {
        // A type in a friend assembly (InternalsVisibleTo) that implements ISanitizingLogger<T>
        // must NOT be exempt — only types defined in ZeeKayDa.Auth itself are trusted.
        var coreSource = """
            using Microsoft.Extensions.Logging;
            namespace ZeeKayDa.Auth.Logging
            {
                internal interface ISanitizingLogger<T> : ILogger<T> { }
            }
            """;

        var aspNetCoreSource = """
            using Microsoft.Extensions.Logging;
            using ZeeKayDa.Auth.Logging;
            namespace ZeeKayDa.Auth.AspNetCore.Services
            {
                internal sealed class FriendService : ISanitizingLogger<FriendService>
                {
                    private readonly ILogger<FriendService> _inner;
                    public FriendService(ILogger<FriendService> inner) { _inner = inner; }
                    public System.IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;
                    public bool IsEnabled(LogLevel level) => false;
                    public void Log<TState>(LogLevel level, Microsoft.Extensions.Logging.EventId id, TState state, System.Exception? ex, System.Func<TState, System.Exception?, string> f) { }
                    public void DoWork()
                    {
                        string secret = "s3cr3t";
                        _inner.LogInformation($"secret={secret}"); // must be flagged
                    }
                }
            }
            """;

        var diagnostics = await GetDiagnosticsFromFriendAssemblyAsync(coreSource, aspNetCoreSource);

        diagnostics.Should().ContainSingle()
            .Which.Id.Should().Be(InterpolatedStringLogAnalyzer.DiagnosticId);
    }

    [Fact]
    public async Task Diagnostic_still_fires_inside_friend_assembly_class_implementing_a_PUBLIC_ISanitizingLogger()
    {
        // Regression coverage for ADR 0011 Amendment 2(d): the exemption is gated on
        // `ContainingAssembly.Name == "ZeeKayDa.Auth"` alone (InterpolatedStringLogAnalyzer.
        // IsInLoggerImplementation), not on ISanitizingLogger<T>'s visibility. Making the
        // interface public must not open a new way for a friend (or third-party) assembly's own
        // ISanitizingLogger<T> implementation to self-exempt from the constant-template rule.
        // Identical to Diagnostic_fires_inside_friend_assembly_class_implementing_ISanitizingLogger
        // except the interface is public here — the outcome must be the same either way.
        var coreSource = """
            using Microsoft.Extensions.Logging;
            namespace ZeeKayDa.Auth.Logging
            {
                public interface ISanitizingLogger<T> : ILogger<T> { }
            }
            """;

        var aspNetCoreSource = """
            using Microsoft.Extensions.Logging;
            using ZeeKayDa.Auth.Logging;
            namespace ZeeKayDa.Auth.AspNetCore.Services
            {
                internal sealed class FriendService : ISanitizingLogger<FriendService>
                {
                    private readonly ILogger<FriendService> _inner;
                    public FriendService(ILogger<FriendService> inner) { _inner = inner; }
                    public System.IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;
                    public bool IsEnabled(LogLevel level) => false;
                    public void Log<TState>(LogLevel level, Microsoft.Extensions.Logging.EventId id, TState state, System.Exception? ex, System.Func<TState, System.Exception?, string> f) { }
                    public void DoWork()
                    {
                        string secret = "s3cr3t";
                        _inner.LogInformation($"secret={secret}"); // must be flagged
                    }
                }
            }
            """;

        var diagnostics = await GetDiagnosticsFromFriendAssemblyAsync(coreSource, aspNetCoreSource);

        diagnostics.Should().ContainSingle()
            .Which.Id.Should().Be(InterpolatedStringLogAnalyzer.DiagnosticId);
    }

    [Fact]
    public async Task Diagnostic_fires_on_conditional_access_LogInformation_call()
    {
        // logger?.LogInformation(...) uses MemberBindingExpressionSyntax rather than
        // MemberAccessExpressionSyntax and must be caught the same way logger.LogInformation(...) is.
        var source = """
            using Microsoft.Extensions.Logging;
            namespace ZeeKayDa.Auth.Logging
            {
                internal interface ISanitizingLogger<T> : ILogger<T> { }
            }
            namespace ZeeKayDa.Auth.Services
            {
                using ZeeKayDa.Auth.Logging;
                class MyService
                {
                    void DoWork()
                    {
                        ISanitizingLogger<object>? logger = null;
                        string value = "x";
                        logger?.LogInformation($"client_secret={value}");
                    }
                }
            }
            """;

        var diagnostics = await GetDiagnosticsAsync(source);

        diagnostics.Should().ContainSingle()
            .Which.Id.Should().Be(InterpolatedStringLogAnalyzer.DiagnosticId);
    }

    [Fact]
    public async Task No_diagnostic_for_conditional_access_LogInformation_call_with_constant_template()
    {
        var source = """
            using Microsoft.Extensions.Logging;
            namespace ZeeKayDa.Auth.Logging
            {
                internal interface ISanitizingLogger<T> : ILogger<T> { }
            }
            namespace ZeeKayDa.Auth.Services
            {
                using ZeeKayDa.Auth.Logging;
                class MyService
                {
                    void DoWork()
                    {
                        ISanitizingLogger<object>? logger = null;
                        string value = "x";
                        logger?.LogInformation("Value: {Value}", value);
                    }
                }
            }
            """;

        var diagnostics = await GetDiagnosticsAsync(source);

        diagnostics.Should().BeEmpty();
    }

    [Fact]
    public async Task No_diagnostic_for_conditional_access_call_on_a_non_ILogger_receiver()
    {
        // The conditional-access receiver must resolve to the correct expression (an
        // ILogger-typed receiver), not just "some non-null receiver" — a Log*-prefixed method on
        // an unrelated type must not be flagged.
        var source = """
            using Microsoft.Extensions.Logging;
            namespace ZeeKayDa.Auth.Services
            {
                class Foo
                {
                    public void LogInformation(string msg) { }
                }
                class MyService
                {
                    void DoWork()
                    {
                        Foo? notALogger = null;
                        string value = "x";
                        notALogger?.LogInformation($"val={value}");
                    }
                }
            }
            """;

        var diagnostics = await GetDiagnosticsAsync(source);

        diagnostics.Should().BeEmpty();
    }

    [Fact]
    public async Task Diagnostic_fires_on_chained_conditional_access_Log_call()
    {
        // GetConditionalAccessReceiver must find the invocation regardless of chain depth: the
        // first link of a fluent `?.` chain (`logger?.LogChain(...).LogChain(...)`) has a
        // MemberAccessExpressionSyntax parent, not the ConditionalAccessExpressionSyntax itself.
        // Log*/AddWarning are void-returning in production, so this chain shape is not reachable
        // through the real APIs today — LogChain below is a test-only fluent helper that returns
        // something chainable purely to exercise this analyzer path.
        var source = """
            using Microsoft.Extensions.Logging;
            namespace ZeeKayDa.Auth.Logging
            {
                internal interface ISanitizingLogger<T> : ILogger<T> { }
            }
            namespace ZeeKayDa.Auth.Services
            {
                using ZeeKayDa.Auth.Logging;
                static class LoggerChainingExtensions
                {
                    public static ISanitizingLogger<object> LogChain(this ISanitizingLogger<object> logger, string message) => logger;
                }
                class MyService
                {
                    void DoWork()
                    {
                        ISanitizingLogger<object>? logger = null;
                        string secret = "s3cr3t";
                        logger?.LogChain($"leak {secret}").LogChain("ok");
                    }
                }
            }
            """;

        var diagnostics = await GetDiagnosticsAsync(source);

        diagnostics.Should().ContainSingle()
            .Which.Id.Should().Be(InterpolatedStringLogAnalyzer.DiagnosticId);
    }

    [Fact]
    public async Task Diagnostic_fires_on_conditional_access_AddWarning_call()
    {
        var source = """
            using Microsoft.Extensions.Logging;
            namespace ZeeKayDa.Auth
            {
                public sealed class StartupVerificationContext
                {
                    public void AddWarning(string code, string messageTemplate, LogLevel level, params object?[] args) { }
                    public void AddWarning(string code, string messageTemplate, params object?[] args) { }
                }
            }
            namespace ZeeKayDa.Auth.Services
            {
                class MyVerifier
                {
                    void DoWork(ZeeKayDa.Auth.StartupVerificationContext? context)
                    {
                        string secret = "s3cr3t";
                        context?.AddWarning("x.code", $"leaked {secret}");
                    }
                }
            }
            """;

        var diagnostics = await GetDiagnosticsAsync(source);

        diagnostics.Should().ContainSingle()
            .Which.Id.Should().Be(InterpolatedStringLogAnalyzer.DiagnosticId);
    }

    // ── AddWarning's messageTemplate (issue #444 follow-up) ──────────────────────────────────────────

    [Fact]
    public async Task Diagnostic_fires_on_interpolated_AddWarning_messageTemplate()
    {
        var source = """
            using Microsoft.Extensions.Logging;
            namespace ZeeKayDa.Auth
            {
                public sealed class StartupVerificationContext
                {
                    public void AddWarning(string code, string messageTemplate, LogLevel level, params object?[] args) { }
                    public void AddWarning(string code, string messageTemplate, params object?[] args) { }
                }
            }
            namespace ZeeKayDa.Auth.Services
            {
                class MyVerifier
                {
                    void DoWork(ZeeKayDa.Auth.StartupVerificationContext context)
                    {
                        string secret = "s3cr3t";
                        context.AddWarning("x.code", $"leaked {secret}");
                    }
                }
            }
            """;

        var diagnostics = await GetDiagnosticsAsync(source);

        diagnostics.Should().ContainSingle()
            .Which.Id.Should().Be(InterpolatedStringLogAnalyzer.DiagnosticId);
    }

    [Fact]
    public async Task Diagnostic_fires_on_AddWarning_messageTemplate_with_LogLevel_overload()
    {
        var source = """
            using Microsoft.Extensions.Logging;
            namespace ZeeKayDa.Auth
            {
                public sealed class StartupVerificationContext
                {
                    public void AddWarning(string code, string messageTemplate, LogLevel level, params object?[] args) { }
                    public void AddWarning(string code, string messageTemplate, params object?[] args) { }
                }
            }
            namespace ZeeKayDa.Auth.Services
            {
                class MyVerifier
                {
                    void DoWork(ZeeKayDa.Auth.StartupVerificationContext context)
                    {
                        string secret = "s3cr3t";
                        context.AddWarning("x.code", $"leaked {secret}", LogLevel.Warning);
                    }
                }
            }
            """;

        var diagnostics = await GetDiagnosticsAsync(source);

        diagnostics.Should().ContainSingle()
            .Which.Id.Should().Be(InterpolatedStringLogAnalyzer.DiagnosticId);
    }

    [Fact]
    public async Task No_diagnostic_for_constant_AddWarning_messageTemplate_with_structured_args()
    {
        var source = """
            using Microsoft.Extensions.Logging;
            namespace ZeeKayDa.Auth
            {
                public sealed class StartupVerificationContext
                {
                    public void AddWarning(string code, string messageTemplate, LogLevel level, params object?[] args) { }
                    public void AddWarning(string code, string messageTemplate, params object?[] args) { }
                }
            }
            namespace ZeeKayDa.Auth.Services
            {
                class MyVerifier
                {
                    void DoWork(ZeeKayDa.Auth.StartupVerificationContext context)
                    {
                        string secret = "s3cr3t";
                        context.AddWarning("x.code", "leaked {Secret}", secret);
                    }
                }
            }
            """;

        var diagnostics = await GetDiagnosticsAsync(source);

        diagnostics.Should().BeEmpty();
    }

    [Fact]
    public async Task No_diagnostic_for_non_constant_AddWarning_code_argument_when_template_is_constant()
    {
        // Documents that "code" (AddWarning's first string parameter) is intentionally NOT the
        // parameter this analyzer constrains — only "messageTemplate" is checked by name/ordinal.
        var source = """
            using Microsoft.Extensions.Logging;
            namespace ZeeKayDa.Auth
            {
                public sealed class StartupVerificationContext
                {
                    public void AddWarning(string code, string messageTemplate, LogLevel level, params object?[] args) { }
                    public void AddWarning(string code, string messageTemplate, params object?[] args) { }
                }
            }
            namespace ZeeKayDa.Auth.Services
            {
                class MyVerifier
                {
                    void DoWork(ZeeKayDa.Auth.StartupVerificationContext context, string dynamicCode)
                    {
                        context.AddWarning(dynamicCode, "a constant template");
                    }
                }
            }
            """;

        var diagnostics = await GetDiagnosticsAsync(source);

        diagnostics.Should().BeEmpty();
    }

    [Fact]
    public async Task No_diagnostic_for_AddWarning_on_an_unrelated_type_with_the_same_method_name()
    {
        // The check is symbol-based (containing type + namespace), not name-based — a same-named
        // AddWarning on some other type must not be constrained.
        var source = """
            namespace ZeeKayDa.Auth.Services
            {
                class SomeOtherAccumulator
                {
                    public void AddWarning(string code, string messageTemplate, params object?[] args) { }
                }
                class MyVerifier
                {
                    void DoWork(SomeOtherAccumulator accumulator)
                    {
                        string secret = "s3cr3t";
                        accumulator.AddWarning("x.code", $"leaked {secret}");
                    }
                }
            }
            """;

        var diagnostics = await GetDiagnosticsAsync(source);

        diagnostics.Should().BeEmpty();
    }

    [Fact]
    public async Task Diagnostic_fires_on_AddWarning_with_a_leading_named_code_argument()
    {
        // A syntax-order-based argument mapping can be fooled by a named "code" argument followed
        // by a positional messageTemplate — the operation-based lookup used here must not be.
        var source = """
            using Microsoft.Extensions.Logging;
            namespace ZeeKayDa.Auth
            {
                public sealed class StartupVerificationContext
                {
                    public void AddWarning(string code, string messageTemplate, LogLevel level, params object?[] args) { }
                    public void AddWarning(string code, string messageTemplate, params object?[] args) { }
                }
            }
            namespace ZeeKayDa.Auth.Services
            {
                class MyVerifier
                {
                    void DoWork(ZeeKayDa.Auth.StartupVerificationContext context)
                    {
                        string secret = "s3cr3t";
                        context.AddWarning(code: "x.code", $"leaked {secret}");
                    }
                }
            }
            """;

        var diagnostics = await GetDiagnosticsAsync(source);

        diagnostics.Should().ContainSingle()
            .Which.Id.Should().Be(InterpolatedStringLogAnalyzer.DiagnosticId);
    }

    [Fact]
    public async Task Diagnostic_fires_on_AddWarning_with_messageTemplate_passed_by_name_out_of_order()
    {
        var source = """
            using Microsoft.Extensions.Logging;
            namespace ZeeKayDa.Auth
            {
                public sealed class StartupVerificationContext
                {
                    public void AddWarning(string code, string messageTemplate, LogLevel level, params object?[] args) { }
                    public void AddWarning(string code, string messageTemplate, params object?[] args) { }
                }
            }
            namespace ZeeKayDa.Auth.Services
            {
                class MyVerifier
                {
                    void DoWork(ZeeKayDa.Auth.StartupVerificationContext context)
                    {
                        string secret = "s3cr3t";
                        context.AddWarning(messageTemplate: $"leaked {secret}", code: "x.code");
                    }
                }
            }
            """;

        var diagnostics = await GetDiagnosticsAsync(source);

        diagnostics.Should().ContainSingle()
            .Which.Id.Should().Be(InterpolatedStringLogAnalyzer.DiagnosticId);
    }

    [Fact]
    public async Task No_diagnostic_for_AddWarning_outside_ZeeKayDa_namespace()
    {
        var source = """
            using Microsoft.Extensions.Logging;
            namespace ZeeKayDa.Auth
            {
                public sealed class StartupVerificationContext
                {
                    public void AddWarning(string code, string messageTemplate, LogLevel level, params object?[] args) { }
                    public void AddWarning(string code, string messageTemplate, params object?[] args) { }
                }
            }
            namespace MyApp.Services
            {
                class MyVerifier
                {
                    void DoWork(ZeeKayDa.Auth.StartupVerificationContext context)
                    {
                        string secret = "s3cr3t";
                        context.AddWarning("x.code", $"leaked {secret}");
                    }
                }
            }
            """;

        var diagnostics = await GetDiagnosticsAsync(source);

        diagnostics.Should().BeEmpty();
    }

    [Fact]
    public void The_real_StartupVerificationContext_AddWarning_still_matches_the_analyzer_s_hardcoded_names()
    {
        // AnalyzeAddWarningInvocation matches by hardcoded strings ("StartupVerificationContext",
        // "ZeeKayDa.Auth", "messageTemplate") against a FAKE type declared in this test file's own
        // source above — not against the real production type. A rename of the real type/method/
        // parameter would silently disable the rule while every test above stayed green. This test
        // is the tripwire: it fails the moment the real symbol and the analyzer's hardcoded match
        // drift apart, forcing both to be updated together.
        var contextType = typeof(ZeeKayDa.Auth.StartupVerificationContext);
        contextType.Namespace.Should().Be("ZeeKayDa.Auth");

        var addWarningMethods = contextType.GetMethods().Where(m => m.Name == "AddWarning").ToList();
        addWarningMethods.Should().NotBeEmpty("the analyzer matches ZeeKayDa.Auth.StartupVerificationContext.AddWarning by name");

        addWarningMethods.Should().OnlyContain(
            m => m.GetParameters().Any(p => p.Name == "messageTemplate"),
            "the analyzer locates its constant-template check via a parameter literally named messageTemplate");
    }

    // ── No diagnostic ─────────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task No_diagnostic_for_string_literal_template()
    {
        var source = """
            using Microsoft.Extensions.Logging;
            namespace ZeeKayDa.Auth.Logging
            {
                internal interface ISanitizingLogger<T> : ILogger<T> { }
            }
            namespace ZeeKayDa.Auth.Services
            {
                using ZeeKayDa.Auth.Logging;
                class MyService
                {
                    void DoWork()
                    {
                        ISanitizingLogger<object> logger = null!;
                        string issuer = "https://example.com";
                        logger.LogInformation("Issuer: {Issuer}", issuer);
                    }
                }
            }
            """;

        var diagnostics = await GetDiagnosticsAsync(source);

        diagnostics.Should().BeEmpty();
    }

    [Fact]
    public async Task No_diagnostic_for_literal_concatenation_template()
    {
        var source = """
            using Microsoft.Extensions.Logging;
            namespace ZeeKayDa.Auth.Logging
            {
                internal interface ISanitizingLogger<T> : ILogger<T> { }
            }
            namespace ZeeKayDa.Auth.Services
            {
                using ZeeKayDa.Auth.Logging;
                class MyService
                {
                    void DoWork()
                    {
                        ISanitizingLogger<object> logger = null!;
                        string x = "a";
                        string y = "b";
                        logger.LogInformation("part one {X} " + "part two {Y}", x, y);
                    }
                }
            }
            """;

        var diagnostics = await GetDiagnosticsAsync(source);

        diagnostics.Should().BeEmpty();
    }

    [Fact]
    public async Task No_diagnostic_outside_ZeeKayDa_namespace()
    {
        var source = """
            using Microsoft.Extensions.Logging;
            namespace MyApp.Services
            {
                class MyService
                {
                    void DoWork()
                    {
                        ILogger<object> logger = null!;
                        string s = "x";
                        logger.LogInformation($"secret={s}");
                    }
                }
            }
            """;

        var diagnostics = await GetDiagnosticsAsync(source);

        diagnostics.Should().BeEmpty();
    }

    [Fact]
    public async Task No_diagnostic_in_logger_implementation_class()
    {
        var source = """
            using System;
            using Microsoft.Extensions.Logging;
            namespace ZeeKayDa.Auth.Logging
            {
                internal interface ISanitizingLogger<T> : ILogger<T> { }
                internal sealed class SecretSanitizingLogger<T> : ISanitizingLogger<T>
                {
                    private readonly ILogger<T> _inner;
                    public SecretSanitizingLogger(ILogger<T> inner) { _inner = inner; }
                    public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;
                    public bool IsEnabled(LogLevel level) => false;
                    public void Log<TState>(LogLevel level, EventId id, TState state, Exception? ex, Func<TState, Exception?, string> f)
                    {
                        string msg = "non-constant " + level.ToString();
                        _inner.LogInformation(msg);
                    }
                }
            }
            """;

        var diagnostics = await GetDiagnosticsAsync(source);

        diagnostics.Should().BeEmpty();
    }

    [Fact]
    public async Task No_diagnostic_for_non_logger_receiver()
    {
        var source = """
            using Microsoft.Extensions.Logging;
            namespace ZeeKayDa.Auth.Services
            {
                class Foo
                {
                    public void LogResult(string msg) { }
                }
                class MyService
                {
                    void DoWork()
                    {
                        Foo foo = null!;
                        string v = "x";
                        foo.LogResult($"val={v}");
                    }
                }
            }
            """;

        var diagnostics = await GetDiagnosticsAsync(source);

        diagnostics.Should().BeEmpty();
    }

    [Fact]
    public async Task No_diagnostic_for_non_Log_method_on_ILogger()
    {
        // Exercises the early-return branch: method name does not start with "Log"
        var source = """
            using Microsoft.Extensions.Logging;
            namespace ZeeKayDa.Auth.Services
            {
                class MyService
                {
                    void DoWork()
                    {
                        ILogger<object> logger = null!;
                        string v = "x";
                        bool result = logger.IsEnabled(LogLevel.Information);
                    }
                }
            }
            """;

        var diagnostics = await GetDiagnosticsAsync(source);

        diagnostics.Should().BeEmpty();
    }

    [Fact]
    public async Task No_diagnostic_inside_ZeeKayDa_Auth_Analyzers_namespace()
    {
        // Exercises the namespace-exclusion branch: ZeeKayDa.Auth.Analyzers is exempt
        var source = """
            using Microsoft.Extensions.Logging;
            namespace ZeeKayDa.Auth.Analyzers
            {
                class AnalyzerHelper
                {
                    void DoWork()
                    {
                        ILogger<object> logger = null!;
                        string v = "x";
                        logger.LogInformation($"msg={v}");
                    }
                }
            }
            """;

        var diagnostics = await GetDiagnosticsAsync(source);

        diagnostics.Should().BeEmpty();
    }

    [Fact]
    public async Task No_diagnostic_for_dynamic_structured_logging_value_after_constant_template()
    {
        // Exercises the "break after first string arg" logic: the second string arg is
        // intentionally dynamic (structured-logging value) and must not trigger a diagnostic.
        var source = """
            using Microsoft.Extensions.Logging;
            namespace ZeeKayDa.Auth.Logging
            {
                internal interface ISanitizingLogger<T> : ILogger<T> { }
            }
            namespace ZeeKayDa.Auth.Services
            {
                using ZeeKayDa.Auth.Logging;
                class MyService
                {
                    void DoWork()
                    {
                        ISanitizingLogger<object> logger = null!;
                        string clientId = "abc";
                        logger.LogInformation("Client authenticated: {ClientId}", clientId);
                    }
                }
            }
            """;

        var diagnostics = await GetDiagnosticsAsync(source);

        diagnostics.Should().BeEmpty();
    }

    [Fact]
    public async Task Diagnostic_fires_when_receiver_is_plain_ILogger_non_generic()
    {
        // Exercises the IsNonGenericILogger direct-match path (not via AllInterfaces)
        var source = """
            using Microsoft.Extensions.Logging;
            namespace ZeeKayDa.Auth.Services
            {
                class MyService
                {
                    void DoWork()
                    {
                        ILogger logger = null!;
                        string v = "x";
                        logger.Log(LogLevel.Information, $"msg={v}");
                    }
                }
            }
            """;

        var diagnostics = await GetDiagnosticsAsync(source);

        diagnostics.Should().ContainSingle()
            .Which.Id.Should().Be(InterpolatedStringLogAnalyzer.DiagnosticId);
    }

    // ── Infrastructure ────────────────────────────────────────────────────────────────────────────

    private static async Task<ImmutableArray<Diagnostic>> GetDiagnosticsAsync(string source)
    {
        var references = new MetadataReference[]
        {
            MetadataReference.CreateFromFile(typeof(object).Assembly.Location),
            MetadataReference.CreateFromFile(typeof(Microsoft.Extensions.Logging.ILogger<>).Assembly.Location),
        };

        var compilation = CSharpCompilation.Create(
            "ZeeKayDa.Auth",
            new[] { CSharpSyntaxTree.ParseText(source) },
            references,
            new CSharpCompilationOptions(OutputKind.DynamicallyLinkedLibrary));

        var analyzers = ImmutableArray.Create<DiagnosticAnalyzer>(new InterpolatedStringLogAnalyzer());
        var compilationWithAnalyzers = compilation.WithAnalyzers(analyzers);
        return await compilationWithAnalyzers.GetAnalyzerDiagnosticsAsync();
    }

    private static async Task<ImmutableArray<Diagnostic>> GetDiagnosticsFromFriendAssemblyAsync(
        string coreSource, string friendSource)
    {
        var sharedReferences = new MetadataReference[]
        {
            MetadataReference.CreateFromFile(typeof(object).Assembly.Location),
            MetadataReference.CreateFromFile(typeof(Microsoft.Extensions.Logging.ILogger<>).Assembly.Location),
        };

        // Compile the core assembly (ZeeKayDa.Auth) that defines ISanitizingLogger<T>
        var coreCompilation = CSharpCompilation.Create(
            "ZeeKayDa.Auth",
            new[] { CSharpSyntaxTree.ParseText(coreSource) },
            sharedReferences,
            new CSharpCompilationOptions(OutputKind.DynamicallyLinkedLibrary));

        // Compile the friend assembly referencing it
        var friendCompilation = CSharpCompilation.Create(
            "ZeeKayDa.Auth.AspNetCore",
            new[] { CSharpSyntaxTree.ParseText(friendSource) },
            sharedReferences.Append(coreCompilation.ToMetadataReference()).ToArray(),
            new CSharpCompilationOptions(OutputKind.DynamicallyLinkedLibrary));

        var analyzers = ImmutableArray.Create<DiagnosticAnalyzer>(new InterpolatedStringLogAnalyzer());
        var compilationWithAnalyzers = friendCompilation.WithAnalyzers(analyzers);
        return await compilationWithAnalyzers.GetAnalyzerDiagnosticsAsync();
    }
}
