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

    // ── Infrastructure ────────────────────────────────────────────────────────────────────────────

    private static async Task<ImmutableArray<Diagnostic>> GetDiagnosticsAsync(
        string source, string assemblyName = "ZeeKayDa.Auth")
    {
        var references = new MetadataReference[]
        {
            MetadataReference.CreateFromFile(typeof(object).Assembly.Location),
            MetadataReference.CreateFromFile(typeof(Microsoft.Extensions.Logging.ILogger<>).Assembly.Location),
        };

        var compilation = CSharpCompilation.Create(
            assemblyName,
            new[] { CSharpSyntaxTree.ParseText(source) },
            references,
            new CSharpCompilationOptions(OutputKind.DynamicallyLinkedLibrary));

        var analyzers = ImmutableArray.Create<DiagnosticAnalyzer>(new ILoggerDirectUseAnalyzer());
        var compilationWithAnalyzers = compilation.WithAnalyzers(analyzers);
        return await compilationWithAnalyzers.GetAnalyzerDiagnosticsAsync();
    }
}
