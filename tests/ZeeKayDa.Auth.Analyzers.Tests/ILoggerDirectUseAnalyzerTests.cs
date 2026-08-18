using System.Collections.Immutable;
using FluentAssertions;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.Diagnostics;
using ZeeKayDa.Auth.Analyzers;

namespace ZeeKayDa.Auth.Analyzers.Tests;

public sealed class ILoggerDirectUseAnalyzerTests
{
    // ── Diagnostic fires ──────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task Diagnostic_fires_on_ILoggerT_constructor_parameter_in_ZeeKayDa_namespace()
    {
        var source = """
            using Microsoft.Extensions.Logging;
            namespace ZeeKayDa.Auth.Services;
            class MyService
            {
                public MyService(ILogger<MyService> logger) { }
            }
            """;

        var diagnostics = await GetDiagnosticsAsync(source);

        diagnostics.Should().ContainSingle()
            .Which.Id.Should().Be(ILoggerDirectUseAnalyzer.DiagnosticId);
    }

    [Fact]
    public async Task Diagnostic_fires_on_ILoggerT_field_in_ZeeKayDa_namespace()
    {
        var source = """
            using Microsoft.Extensions.Logging;
            namespace ZeeKayDa.Auth.Services;
            class MyService
            {
                private readonly ILogger<MyService> _logger = null!;
            }
            """;

        var diagnostics = await GetDiagnosticsAsync(source);

        diagnostics.Should().ContainSingle()
            .Which.Id.Should().Be(ILoggerDirectUseAnalyzer.DiagnosticId);
    }

    // ── No diagnostic ─────────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task No_diagnostic_for_ISanitizingLogger_parameter_in_ZeeKayDa_namespace()
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
                    public MyService(ISanitizingLogger<MyService> logger) { }
                }
            }
            """;

        var diagnostics = await GetDiagnosticsAsync(source);

        diagnostics.Should().BeEmpty();
    }

    [Fact]
    public async Task No_diagnostic_for_ILoggerT_parameter_in_ZeeKayDa_Auth_Analyzers_assembly()
    {
        // The analyzer project itself lives in ZeeKayDa.Auth.Analyzers and must be exempt so
        // that adding logging to analyzer code does not create a circular dependency.
        var source = """
            using Microsoft.Extensions.Logging;
            namespace ZeeKayDa.Auth.Analyzers;
            class MyAnalyzer
            {
                public MyAnalyzer(ILogger<MyAnalyzer> logger) { }
            }
            """;

        var diagnostics = await GetDiagnosticsAsync(source, assemblyName: "ZeeKayDa.Auth.Analyzers");

        diagnostics.Should().BeEmpty();
    }

    [Fact]
    public async Task No_diagnostic_for_ILoggerT_parameter_outside_the_ZeeKayDa_Auth_assembly()
    {
        var source = """
            using Microsoft.Extensions.Logging;
            namespace MyApp.Services;
            class MyService
            {
                public MyService(ILogger<MyService> logger) { }
            }
            """;

        var diagnostics = await GetDiagnosticsAsync(source, assemblyName: "MyApp");

        diagnostics.Should().BeEmpty();
    }

    [Fact]
    public async Task Diagnostic_fires_for_ZeeKayDa_Auth_assembly_code_declared_in_a_Microsoft_namespace()
    {
        // Regression coverage for security finding F1: the gate must key off the compilation's
        // assembly, not the syntactic namespace text — ZeeKayDa.Auth's own extension-method
        // classes commonly declare themselves under a Microsoft.* namespace for discoverability,
        // and must not thereby escape analysis.
        var source = """
            using Microsoft.Extensions.Logging;
            namespace Microsoft.Extensions.DependencyInjection;
            class ServiceCollectionExtensions
            {
                public ServiceCollectionExtensions(ILogger<ServiceCollectionExtensions> logger) { }
            }
            """;

        var diagnostics = await GetDiagnosticsAsync(source, assemblyName: "ZeeKayDa.Auth.AspNetCore");

        diagnostics.Should().ContainSingle()
            .Which.Id.Should().Be(ILoggerDirectUseAnalyzer.DiagnosticId);
    }

    [Fact]
    public async Task No_diagnostic_for_field_typed_as_non_generic_ILogger()
    {
        // IsDirectILoggerT returns false when namedType.IsGenericType is false,
        // so a bare ILogger field (not ILogger<T>) must not trigger the diagnostic.
        var source = """
            using Microsoft.Extensions.Logging;
            namespace ZeeKayDa.Auth.Services;
            class MyService
            {
                private ILogger _logger = null!;
            }
            """;

        var diagnostics = await GetDiagnosticsAsync(source);

        diagnostics.Should().BeEmpty();
    }

    [Fact]
    public async Task No_diagnostic_for_ILoggerT_parameter_in_class_that_implements_ILoggerT()
    {
        // SecretSanitizingLogger itself accepts ILogger<T> as its inner wrapper target;
        // the analyzer must not fire on classes that ARE the ILogger<T> implementation.
        var source = """
            using System;
            using System.Collections.Generic;
            using Microsoft.Extensions.Logging;
            namespace ZeeKayDa.Auth.Logging
            {
                internal interface ISanitizingLogger<T> : ILogger<T> { }
                internal sealed class SecretSanitizingLogger<T> : ISanitizingLogger<T>
                {
                    public SecretSanitizingLogger(ILogger<T> inner) { }
                    public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;
                    public bool IsEnabled(LogLevel level) => false;
                    public void Log<TState>(LogLevel level, EventId id, TState state, Exception? ex, Func<TState, Exception?, string> f) { }
                }
            }
            """;

        var diagnostics = await GetDiagnosticsAsync(source);

        diagnostics.Should().BeEmpty();
    }

    // ── Generated code is still analyzed (ZEEKAYDA0001 is a security control; see #467) ─────────────

    [Fact]
    public async Task Diagnostic_fires_when_file_name_matches_a_generated_code_convention()
    {
        var source = """
            using Microsoft.Extensions.Logging;
            namespace ZeeKayDa.Auth.Services;
            class MyService
            {
                public MyService(ILogger<MyService> logger) { }
            }
            """;

        var diagnostics = await GetDiagnosticsAsync(source, path: "MyService.designer.cs");

        diagnostics.Should().ContainSingle()
            .Which.Id.Should().Be(ILoggerDirectUseAnalyzer.DiagnosticId);
    }

    [Fact]
    public async Task Diagnostic_fires_when_source_has_an_auto_generated_header()
    {
        var source = """
            // <auto-generated/>
            using Microsoft.Extensions.Logging;
            namespace ZeeKayDa.Auth.Services;
            class MyService
            {
                public MyService(ILogger<MyService> logger) { }
            }
            """;

        var diagnostics = await GetDiagnosticsAsync(source);

        diagnostics.Should().ContainSingle()
            .Which.Id.Should().Be(ILoggerDirectUseAnalyzer.DiagnosticId);
    }

    [Fact]
    public async Task Diagnostic_fires_on_a_type_carrying_the_GeneratedCode_attribute()
    {
        var source = """
            using System.CodeDom.Compiler;
            using Microsoft.Extensions.Logging;
            namespace ZeeKayDa.Auth.Services;

            [GeneratedCode("tool", "1.0")]
            class MyService
            {
                public MyService(ILogger<MyService> logger) { }
            }
            """;

        var diagnostics = await GetDiagnosticsAsync(source);

        diagnostics.Should().ContainSingle()
            .Which.Id.Should().Be(ILoggerDirectUseAnalyzer.DiagnosticId);
    }

    [Fact]
    public async Task Diagnostic_fires_when_editorconfig_marks_the_path_as_generated_code()
    {
        var source = """
            using Microsoft.Extensions.Logging;
            namespace ZeeKayDa.Auth.Services;
            class MyService
            {
                public MyService(ILogger<MyService> logger) { }
            }
            """;
        const string path = "MyService.cs";

        var diagnostics = await GetDiagnosticsAsync(
            source,
            path: path,
            optionsProvider: new GeneratedCodeConfigOptionsProvider(path));

        diagnostics.Should().ContainSingle()
            .Which.Id.Should().Be(ILoggerDirectUseAnalyzer.DiagnosticId);
    }

    // ── Infrastructure ────────────────────────────────────────────────────────────────────────────

    private static async Task<ImmutableArray<Diagnostic>> GetDiagnosticsAsync(
        string source,
        string assemblyName = "ZeeKayDa.Auth",
        string path = "",
        AnalyzerConfigOptionsProvider? optionsProvider = null)
    {
        var references = new MetadataReference[]
        {
            MetadataReference.CreateFromFile(typeof(object).Assembly.Location),
            MetadataReference.CreateFromFile(typeof(Microsoft.Extensions.Logging.ILogger<>).Assembly.Location),
        };

        var compilation = CSharpCompilation.Create(
            assemblyName,
            new[] { CSharpSyntaxTree.ParseText(source, path: path) },
            references,
            new CSharpCompilationOptions(OutputKind.DynamicallyLinkedLibrary));

        var analyzers = ImmutableArray.Create<DiagnosticAnalyzer>(new ILoggerDirectUseAnalyzer());
        var analyzerOptions = new AnalyzerOptions(
            ImmutableArray<AdditionalText>.Empty, optionsProvider ?? GeneratedCodeConfigOptionsProvider.None);
        var compilationWithAnalyzers = compilation.WithAnalyzers(analyzers, analyzerOptions);
        return await compilationWithAnalyzers.GetAnalyzerDiagnosticsAsync();
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
