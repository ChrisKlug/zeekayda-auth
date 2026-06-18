using System.Collections.Immutable;
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
            "TestAssembly",
            new[] { CSharpSyntaxTree.ParseText(source) },
            references,
            new CSharpCompilationOptions(OutputKind.DynamicallyLinkedLibrary));

        var analyzers = ImmutableArray.Create<DiagnosticAnalyzer>(new InterpolatedStringLogAnalyzer());
        var compilationWithAnalyzers = compilation.WithAnalyzers(analyzers);
        return await compilationWithAnalyzers.GetAnalyzerDiagnosticsAsync();
    }
}
