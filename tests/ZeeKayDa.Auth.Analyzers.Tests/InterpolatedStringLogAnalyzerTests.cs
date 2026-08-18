using System;
using System.Collections.Immutable;
using System.IO;
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
            using System.Runtime.CompilerServices;
            using Microsoft.Extensions.Logging;
            [assembly: InternalsVisibleTo("ZeeKayDa.Auth.AspNetCore")]
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

    [Fact]
    public async Task Diagnostic_fires_on_unqualified_AddWarning_call_with_implicit_this()
    {
        // AddWarning called from inside StartupVerificationContext itself, with an implicit
        // `this` receiver, uses IdentifierNameSyntax rather than MemberAccessExpressionSyntax —
        // it must still be caught.
        var source = """
            using Microsoft.Extensions.Logging;
            namespace ZeeKayDa.Auth
            {
                public sealed class StartupVerificationContext
                {
                    public void AddWarning(string code, string messageTemplate, LogLevel level, params object?[] args) { }
                    public void DoWork()
                    {
                        string secret = "s3cr3t";
                        AddWarning("x.code", $"leaked {secret}", LogLevel.Warning);
                    }
                }
            }
            """;

        var diagnostics = await GetDiagnosticsAsync(source);

        diagnostics.Should().ContainSingle()
            .Which.Id.Should().Be(InterpolatedStringLogAnalyzer.DiagnosticId);
    }

    [Fact]
    public async Task Diagnostic_fires_when_one_AddWarning_overload_forwards_to_another_by_name()
    {
        // There is no longer any exemption for AddWarning-calling-AddWarning: forwarding a
        // non-constant messageTemplate parameter into a same-named sibling overload is flagged
        // exactly like any other non-constant template. The real StartupVerificationContext
        // avoids this by forwarding into a private AddWarningCore helper instead (see
        // No_diagnostic_for_AddWarning_overloads_that_forward_into_a_private_AddWarningCore_helper).
        var source = """
            using Microsoft.Extensions.Logging;
            namespace ZeeKayDa.Auth
            {
                public sealed class StartupVerificationContext
                {
                    public void AddWarning(string code, string messageTemplate, LogLevel level, params object?[] args) { }

                    public void AddWarning(string code, string messageTemplate, params object?[] args)
                        => AddWarning(code, messageTemplate, LogLevel.Warning, args);
                }
            }
            """;

        var diagnostics = await GetDiagnosticsAsync(source);

        diagnostics.Should().ContainSingle()
            .Which.Id.Should().Be(InterpolatedStringLogAnalyzer.DiagnosticId);
    }

    [Fact]
    public async Task Diagnostic_fires_when_a_static_AddWarning_overload_forwards_to_another_by_name()
    {
        // Regression coverage for architect finding A1(a): MethodKind.Ordinary is also true for
        // static methods, so a static AddWarning overload forwarding to a sibling overload must
        // be flagged the same as an instance one — there is no longer any AddWarning-specific
        // forwarding exemption at all.
        var source = """
            using Microsoft.Extensions.Logging;
            namespace ZeeKayDa.Auth
            {
                public sealed class StartupVerificationContext
                {
                    public static void AddWarning(string code, string messageTemplate, LogLevel level, params object?[] args) { }

                    public static void AddWarning(string code, string messageTemplate, params object?[] args)
                        => AddWarning(code, messageTemplate, LogLevel.Warning, args);
                }
            }
            """;

        var diagnostics = await GetDiagnosticsAsync(source);

        diagnostics.Should().ContainSingle()
            .Which.Id.Should().Be(InterpolatedStringLogAnalyzer.DiagnosticId);
    }

    [Fact]
    public async Task Diagnostic_fires_when_messageTemplate_is_reassigned_before_forwarding_to_another_AddWarning()
    {
        // Regression coverage for architect finding A1(b): reassigning messageTemplate before the
        // forwarding call previously still passed the exemption, because the reference at the call
        // site was still an IParameterReferenceOperation even though its value had been mutated.
        // With the exemption removed entirely this is moot, but the case is kept as a tripwire.
        var source = """
            using Microsoft.Extensions.Logging;
            namespace ZeeKayDa.Auth
            {
                public sealed class StartupVerificationContext
                {
                    public void AddWarning(string code, string messageTemplate, LogLevel level, params object?[] args) { }

                    public void AddWarning(string code, string messageTemplate, params object?[] args)
                    {
                        messageTemplate = messageTemplate;
                        AddWarning(code, messageTemplate, LogLevel.Warning, args);
                    }
                }
            }
            """;

        var diagnostics = await GetDiagnosticsAsync(source);

        diagnostics.Should().ContainSingle()
            .Which.Id.Should().Be(InterpolatedStringLogAnalyzer.DiagnosticId);
    }

    [Fact]
    public async Task No_diagnostic_for_AddWarning_overloads_that_forward_into_a_private_AddWarningCore_helper()
    {
        // Mirrors the real StartupVerificationContext structure: both public AddWarning overloads
        // forward into a private AddWarningCore helper rather than calling each other. The
        // analyzer's AddWarning dispatch is name-based (methodName == "AddWarning"), so a call to
        // AddWarningCore is never routed into AnalyzeAddWarningInvocation in the first place — the
        // safety guarantee is that AddWarningCore is private and therefore unreachable from
        // anywhere outside these two overloads.
        var source = """
            using Microsoft.Extensions.Logging;
            namespace ZeeKayDa.Auth
            {
                public sealed class StartupVerificationContext
                {
                    public void AddWarning(string code, string messageTemplate, LogLevel level, params object?[] args)
                        => AddWarningCore(code, messageTemplate, level, args);

                    public void AddWarning(string code, string messageTemplate, params object?[] args)
                        => AddWarningCore(code, messageTemplate, LogLevel.Warning, args);

                    private void AddWarningCore(string code, string messageTemplate, LogLevel level, object?[] args) { }
                }
            }
            """;

        var diagnostics = await GetDiagnosticsAsync(source);

        diagnostics.Should().BeEmpty();
    }

    [Fact]
    public async Task Diagnostic_fires_for_unrelated_type_forwarding_a_variable_named_messageTemplate()
    {
        // The check is scoped to StartupVerificationContext itself (matched by symbol) — an
        // unrelated type that happens to declare a parameter also named "messageTemplate" and
        // forwards it into AddWarning must still be flagged.
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
                    void Forward(ZeeKayDa.Auth.StartupVerificationContext context, string messageTemplate)
                        => context.AddWarning("x.code", messageTemplate);
                }
            }
            """;

        var diagnostics = await GetDiagnosticsAsync(source);

        diagnostics.Should().ContainSingle()
            .Which.Id.Should().Be(InterpolatedStringLogAnalyzer.DiagnosticId);
    }

    [Fact]
    public async Task Diagnostic_fires_for_messageTemplate_parameter_forwarded_from_StartupVerificationContext_constructor()
    {
        // Regression coverage for architect finding 3 / security F2: the forwarding exemption
        // previously accepted a "messageTemplate" parameter declared on ANY member of
        // StartupVerificationContext, not just an AddWarning overload — a constructor parameter of
        // that name could launder an interpolated string through unflagged.
        var source = """
            using Microsoft.Extensions.Logging;
            namespace ZeeKayDa.Auth
            {
                public sealed class StartupVerificationContext
                {
                    public void AddWarning(string code, string messageTemplate, params object?[] args) { }

                    public StartupVerificationContext(string messageTemplate)
                        => AddWarning("x.code", messageTemplate);
                }
            }
            namespace ZeeKayDa.Auth.Services
            {
                class MyVerifier
                {
                    void DoWork()
                    {
                        string secret = "s3cr3t";
                        _ = new ZeeKayDa.Auth.StartupVerificationContext($"leaked {secret}");
                    }
                }
            }
            """;

        var diagnostics = await GetDiagnosticsAsync(source);

        diagnostics.Should().ContainSingle()
            .Which.Id.Should().Be(InterpolatedStringLogAnalyzer.DiagnosticId);
    }

    [Fact]
    public async Task Diagnostic_fires_for_messageTemplate_parameter_forwarded_from_a_private_helper_on_StartupVerificationContext()
    {
        var source = """
            using Microsoft.Extensions.Logging;
            namespace ZeeKayDa.Auth
            {
                public sealed class StartupVerificationContext
                {
                    public void AddWarning(string code, string messageTemplate, params object?[] args) { }

                    private void Forward(string messageTemplate) => AddWarning("x.code", messageTemplate);

                    public void DoWork()
                    {
                        string secret = "s3cr3t";
                        Forward($"leaked {secret}");
                    }
                }
            }
            """;

        var diagnostics = await GetDiagnosticsAsync(source);

        diagnostics.Should().ContainSingle()
            .Which.Id.Should().Be(InterpolatedStringLogAnalyzer.DiagnosticId);
    }

    [Fact]
    public async Task Diagnostic_fires_for_messageTemplate_parameter_forwarded_from_a_lambda_on_StartupVerificationContext()
    {
        var source = """
            using System;
            using Microsoft.Extensions.Logging;
            namespace ZeeKayDa.Auth
            {
                public sealed class StartupVerificationContext
                {
                    public void AddWarning(string code, string messageTemplate, params object?[] args) { }

                    public void DoWork()
                    {
                        Action<string> forward = messageTemplate => AddWarning("x.code", messageTemplate);
                        string secret = "s3cr3t";
                        forward($"leaked {secret}");
                    }
                }
            }
            """;

        var diagnostics = await GetDiagnosticsAsync(source);

        diagnostics.Should().ContainSingle()
            .Which.Id.Should().Be(InterpolatedStringLogAnalyzer.DiagnosticId);
    }

    [Fact]
    public async Task Diagnostic_fires_on_static_extension_method_call_form()
    {
        // LoggerExtensions.LogInformation(logger, "...") is the static-method call form of the
        // same extension method `logger.LogInformation(...)` binds to — the receiver expression
        // names the declaring type, not a logger value, and must be resolved via the first
        // argument instead.
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
                        string secret = "s3cr3t";
                        LoggerExtensions.LogInformation(logger, $"leak {secret}");
                    }
                }
            }
            """;

        var diagnostics = await GetDiagnosticsAsync(source);

        diagnostics.Should().ContainSingle()
            .Which.Id.Should().Be(InterpolatedStringLogAnalyzer.DiagnosticId);
    }

    [Fact]
    public async Task No_diagnostic_for_static_extension_method_call_form_with_constant_template()
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
                        LoggerExtensions.LogInformation(logger, "Value: {Value}", value);
                    }
                }
            }
            """;

        var diagnostics = await GetDiagnosticsAsync(source);

        diagnostics.Should().BeEmpty();
    }

    [Fact]
    public async Task No_diagnostic_for_unrelated_extension_method_with_an_ILogger_typed_first_argument()
    {
        // Regression coverage for the architect-reported false positive: an unrelated Log*-named
        // extension method's real receiver ("this") is not an ILogger — the fact that its first
        // explicit argument happens to be ILogger-typed must not make ResolveLoggerReceiverType
        // mistake that argument for the receiver.
        var source = """
            using Microsoft.Extensions.Logging;
            namespace ZeeKayDa.Auth.Services
            {
                class AuditTrail { }
                static class AuditTrailExtensions
                {
                    public static void LogAudit(this AuditTrail trail, ILogger logger, string userId) { }
                }
                class MyService
                {
                    void DoWork(AuditTrail trail, ILogger logger)
                    {
                        string userId = "u1";
                        trail.LogAudit(logger, userId);
                    }
                }
            }
            """;

        var diagnostics = await GetDiagnosticsAsync(source);

        diagnostics.Should().BeEmpty();
    }

    [Fact]
    public async Task Diagnostic_fires_on_static_extension_method_call_with_named_reordered_arguments()
    {
        // Regression coverage for the architect-reported bypass: the static-method call form's
        // receiver must be resolved via the operation's argument-to-parameter binding
        // (Parameter.Ordinal == 0), not by assuming the first *syntax* argument is the receiver —
        // otherwise a named/reordered call slips the check entirely.
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
                        string secret = "s3cr3t";
                        LoggerExtensions.LogInformation(message: $"leak {secret}", logger: logger);
                    }
                }
            }
            """;

        var diagnostics = await GetDiagnosticsAsync(source);

        diagnostics.Should().ContainSingle()
            .Which.Id.Should().Be(InterpolatedStringLogAnalyzer.DiagnosticId);
    }

    [Fact]
    public async Task Diagnostic_fires_on_BeginScope_with_interpolated_string()
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
                        string secret = "s3cr3t";
                        using var scope = logger.BeginScope($"leak {secret}");
                    }
                }
            }
            """;

        var diagnostics = await GetDiagnosticsAsync(source);

        diagnostics.Should().ContainSingle()
            .Which.Id.Should().Be(InterpolatedStringLogAnalyzer.DiagnosticId);
    }

    [Fact]
    public async Task No_diagnostic_for_BeginScope_with_constant_template()
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
                        using var scope = logger.BeginScope("Value: {Value}", value);
                    }
                }
            }
            """;

        var diagnostics = await GetDiagnosticsAsync(source);

        diagnostics.Should().BeEmpty();
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
    public async Task No_diagnostic_for_AddWarning_outside_ZeeKayDa_assembly()
    {
        // The gate is on the CALLER's assembly (per ADR/security fix for #460's F1), not the
        // caller's declared namespace — a caller compiled into an unrelated assembly must not be
        // analyzed even though the target type still lives in a "ZeeKayDa.Auth"-named namespace.
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

        var diagnostics = await GetDiagnosticsAsync(source, assemblyName: "MyApp");

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
    public async Task No_diagnostic_outside_ZeeKayDa_assembly()
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

        var diagnostics = await GetDiagnosticsAsync(source, assemblyName: "MyApp");

        diagnostics.Should().BeEmpty();
    }

    [Fact]
    public async Task Diagnostic_fires_for_ZeeKayDa_assembly_code_declared_in_a_Microsoft_namespace()
    {
        // Regression coverage for security finding F1: the gate must key off the compilation's
        // assembly, not the syntactic namespace text — ZeeKayDa.Auth's own extension-method
        // classes commonly declare themselves under a Microsoft.* namespace (e.g.
        // Microsoft.Extensions.DependencyInjection) for discoverability, and must not thereby
        // escape analysis.
        var source = """
            using Microsoft.Extensions.Logging;
            namespace Microsoft.Extensions.DependencyInjection
            {
                internal interface ISanitizingLogger<T> : ILogger<T> { }
                static class ServiceCollectionExtensions
                {
                    static void Configure(ISanitizingLogger<object> logger)
                    {
                        string secret = "s3cr3t";
                        logger.LogInformation($"leak {secret}");
                    }
                }
            }
            """;

        var diagnostics = await GetDiagnosticsAsync(source, assemblyName: "ZeeKayDa.Auth.AspNetCore");

        diagnostics.Should().ContainSingle()
            .Which.Id.Should().Be(InterpolatedStringLogAnalyzer.DiagnosticId);
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
    public async Task No_diagnostic_inside_ZeeKayDa_Auth_Analyzers_assembly()
    {
        // Exercises the assembly-exclusion branch: ZeeKayDa.Auth.Analyzers is exempt
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

        var diagnostics = await GetDiagnosticsAsync(source, assemblyName: "ZeeKayDa.Auth.Analyzers");

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

    // ── Generated code is still analyzed (ZEEKAYDA0002 is a security control; see #467) ─────────────

    [Fact]
    public async Task Diagnostic_fires_when_file_name_matches_a_generated_code_convention()
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

        var diagnostics = await GetDiagnosticsAsync(source, path: "MyService.g.cs");

        diagnostics.Should().ContainSingle()
            .Which.Id.Should().Be(InterpolatedStringLogAnalyzer.DiagnosticId);
    }

    [Fact]
    public async Task Diagnostic_fires_when_source_has_an_auto_generated_header()
    {
        var source = """
            // <auto-generated/>
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
    public async Task Diagnostic_fires_on_a_type_carrying_the_GeneratedCode_attribute()
    {
        var source = """
            using System.CodeDom.Compiler;
            using Microsoft.Extensions.Logging;
            namespace ZeeKayDa.Auth.Logging
            {
                internal interface ISanitizingLogger<T> : ILogger<T> { }
            }
            namespace ZeeKayDa.Auth.Services
            {
                using ZeeKayDa.Auth.Logging;

                [GeneratedCode("tool", "1.0")]
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
    public async Task Diagnostic_fires_when_editorconfig_marks_the_path_as_generated_code()
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
        const string path = "MyService.cs";

        var diagnostics = await GetDiagnosticsAsync(
            source,
            path: path,
            optionsProvider: new GeneratedCodeConfigOptionsProvider(path));

        diagnostics.Should().ContainSingle()
            .Which.Id.Should().Be(InterpolatedStringLogAnalyzer.DiagnosticId);
    }

    // ── Method-group delegate bypass (issue #463) ────────────────────────────────────────────────────

    [Fact]
    public async Task Diagnostic_fires_on_LogInformation_method_group_assigned_to_a_delegate_variable()
    {
        // The later call through `log(...)` has no ILogger-shaped receiver at all to hook into —
        // this is caught at the method-group conversion instead.
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
                        Action<string, object?[]> log = logger.LogInformation;
                        string secret = "s3cr3t";
                        log($"leak {secret}", Array.Empty<object?>());
                    }
                }
            }
            """;

        var diagnostics = await GetDiagnosticsAsync(source);

        diagnostics.Should().ContainSingle()
            .Which.Id.Should().Be(InterpolatedStringLogAnalyzer.DiagnosticId);
    }

    [Fact]
    public async Task Diagnostic_fires_on_AddWarning_method_group_assigned_to_a_field()
    {
        var source = """
            using System;
            using Microsoft.Extensions.Logging;
            namespace ZeeKayDa.Auth
            {
                public sealed class StartupVerificationContext
                {
                    public void AddWarning(string code, string messageTemplate, params object?[] args) { }
                }
            }
            namespace ZeeKayDa.Auth.Services
            {
                class MyVerifier
                {
                    private Action<string, string, object?[]> _warn = null!;

                    void DoWork(ZeeKayDa.Auth.StartupVerificationContext warningsCollector)
                    {
                        _warn = warningsCollector.AddWarning;
                    }
                }
            }
            """;

        var diagnostics = await GetDiagnosticsAsync(source);

        diagnostics.Should().ContainSingle()
            .Which.Id.Should().Be(InterpolatedStringLogAnalyzer.DiagnosticId);
    }

    [Fact]
    public async Task No_diagnostic_for_delegate_assigned_from_an_unrelated_method_group()
    {
        // A method group unrelated to Log*/AddWarning (ordinary delegate usage) must never be
        // flagged, regardless of receiver type or delegate shape.
        var source = """
            using System;
            using Microsoft.Extensions.Logging;
            namespace ZeeKayDa.Auth.Services
            {
                class Formatter
                {
                    public string Format(string template, object?[] args) => template;
                }
                class MyService
                {
                    void DoWork(ILogger logger, Formatter formatter)
                    {
                        Func<string, object?[], string> format = formatter.Format;
                        string result = format("template", Array.Empty<object?>());
                    }
                }
            }
            """;

        var diagnostics = await GetDiagnosticsAsync(source);

        diagnostics.Should().BeEmpty();
    }

    [Fact]
    public async Task No_diagnostic_for_LogInformation_method_group_converted_to_a_delegate_without_a_string_parameter()
    {
        // The delegate shape check means this only flags conversions to a delegate that could
        // plausibly carry a message template — an unrelated delegate shape is not a bypass.
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
                static class LoggerNoArgExtensions
                {
                    public static void LogNoArgs(this ISanitizingLogger<object> logger) { }
                }
                class MyService
                {
                    void DoWork()
                    {
                        ISanitizingLogger<object> logger = null!;
                        Action log = logger.LogNoArgs;
                    }
                }
            }
            """;

        var diagnostics = await GetDiagnosticsAsync(source);

        diagnostics.Should().BeEmpty();
    }

    [Fact]
    public async Task Diagnostic_still_fires_on_a_direct_LogInformation_call_after_the_method_group_check_was_added()
    {
        // Regression guard: the assignment-site check must not interfere with the ordinary
        // direct-call detection it sits alongside.
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
                        string secret = "s3cr3t";
                        logger.LogInformation($"leak {secret}");
                    }
                }
            }
            """;

        var diagnostics = await GetDiagnosticsAsync(source);

        diagnostics.Should().ContainSingle()
            .Which.Id.Should().Be(InterpolatedStringLogAnalyzer.DiagnosticId);
    }

    // ── Infrastructure ────────────────────────────────────────────────────────────────────────────

    private static async Task<ImmutableArray<Diagnostic>> GetDiagnosticsAsync(
        string source,
        string assemblyName = "ZeeKayDa.Auth",
        string path = "",
        AnalyzerConfigOptionsProvider? optionsProvider = null)
    {
        var references = BuildFullReferences();

        var compilation = CSharpCompilation.Create(
            assemblyName,
            new[] { CSharpSyntaxTree.ParseText(source, path: path) },
            references,
            new CSharpCompilationOptions(OutputKind.DynamicallyLinkedLibrary));

        await AssertNoCompilerErrorsAsync(compilation);

        var analyzers = ImmutableArray.Create<DiagnosticAnalyzer>(new InterpolatedStringLogAnalyzer());
        var analyzerOptions = new AnalyzerOptions(
            ImmutableArray<AdditionalText>.Empty, optionsProvider ?? GeneratedCodeConfigOptionsProvider.None);
        var compilationWithAnalyzers = compilation.WithAnalyzers(analyzers, analyzerOptions);
        return await compilationWithAnalyzers.GetAnalyzerDiagnosticsAsync();
    }

    private static async Task<ImmutableArray<Diagnostic>> GetDiagnosticsFromFriendAssemblyAsync(
        string coreSource, string friendSource)
    {
        var sharedReferences = BuildFullReferences();

        // Compile the core assembly (ZeeKayDa.Auth) that defines ISanitizingLogger<T>
        var coreCompilation = CSharpCompilation.Create(
            "ZeeKayDa.Auth",
            new[] { CSharpSyntaxTree.ParseText(coreSource) },
            sharedReferences,
            new CSharpCompilationOptions(OutputKind.DynamicallyLinkedLibrary));
        await AssertNoCompilerErrorsAsync(coreCompilation);

        // Compile the friend assembly referencing it
        var friendCompilation = CSharpCompilation.Create(
            "ZeeKayDa.Auth.AspNetCore",
            new[] { CSharpSyntaxTree.ParseText(friendSource) },
            sharedReferences.Append(coreCompilation.ToMetadataReference()).ToArray(),
            new CSharpCompilationOptions(OutputKind.DynamicallyLinkedLibrary));
        await AssertNoCompilerErrorsAsync(friendCompilation);

        var analyzers = ImmutableArray.Create<DiagnosticAnalyzer>(new InterpolatedStringLogAnalyzer());
        var compilationWithAnalyzers = friendCompilation.WithAnalyzers(analyzers);
        return await compilationWithAnalyzers.GetAnalyzerDiagnosticsAsync();
    }

    // A compilation built from only a couple of hand-picked references binds most real-world
    // snippets incompletely, producing CS0012-style "type defined in an assembly that is not
    // referenced" errors. A negative assertion (diagnostics.Should().BeEmpty()) against such a
    // compilation can pass vacuously, without the analyzer ever actually inspecting the intended
    // code path. Referencing the full trusted-platform-assembly set avoids that, and asserting
    // zero compiler errors here surfaces a broken test snippet as a test failure instead of a
    // silently meaningless assertion.
    private static async Task AssertNoCompilerErrorsAsync(CSharpCompilation compilation)
    {
        var diagnostics = await Task.Run(() => compilation.GetDiagnostics());
        diagnostics.Where(d => d.Severity == DiagnosticSeverity.Error).Should().BeEmpty();
    }

    private static MetadataReference[] BuildFullReferences()
    {
        var trustedAssemblies = ((string)AppContext.GetData("TRUSTED_PLATFORM_ASSEMBLIES")!)
            .Split(Path.PathSeparator);

        // Exclude ZeeKayDa's own assemblies: the fake types these test snippets declare (e.g. a
        // stand-in "ZeeKayDa.Auth.StartupVerificationContext") deliberately shadow the real
        // production types, and referencing both would collide on assembly identity.
        var references = trustedAssemblies
            .Where(path => !Path.GetFileNameWithoutExtension(path).StartsWith("ZeeKayDa.", StringComparison.Ordinal))
            .Select(path => (MetadataReference)MetadataReference.CreateFromFile(path))
            .ToList();

        references.Add(MetadataReference.CreateFromFile(typeof(Microsoft.Extensions.Logging.ILogger<>).Assembly.Location));

        return references.ToArray();
    }

    /// <summary>
    /// Reports <c>generated_code = true</c> (the <c>.editorconfig</c>/<c>.globalconfig</c> key
    /// Roslyn's generated-code heuristic consults) for a single tree path, and nothing for any
    /// other tree.
    /// </summary>
    private sealed class GeneratedCodeConfigOptionsProvider(string? generatedPath) : AnalyzerConfigOptionsProvider
    {
        /// <summary>A provider that never reports <c>generated_code</c>, used as the default when no test-specific provider is supplied.</summary>
        public static readonly GeneratedCodeConfigOptionsProvider None = new(generatedPath: null);

        public override AnalyzerConfigOptions GlobalOptions => EmptyAnalyzerConfigOptions.Instance;

        public override AnalyzerConfigOptions GetOptions(SyntaxTree tree) =>
            generatedPath is not null && tree.FilePath == generatedPath
                ? new GeneratedCodeAnalyzerConfigOptions()
                : EmptyAnalyzerConfigOptions.Instance;

        public override AnalyzerConfigOptions GetOptions(AdditionalText textFile) =>
            EmptyAnalyzerConfigOptions.Instance;

        private sealed class GeneratedCodeAnalyzerConfigOptions : AnalyzerConfigOptions
        {
            public override bool TryGetValue(string key, out string value)
            {
                if (key == "generated_code")
                {
                    value = "true";
                    return true;
                }

                value = "";
                return false;
            }
        }

        private sealed class EmptyAnalyzerConfigOptions : AnalyzerConfigOptions
        {
            public static readonly EmptyAnalyzerConfigOptions Instance = new();

            public override bool TryGetValue(string key, out string value)
            {
                value = "";
                return false;
            }
        }
    }
}
