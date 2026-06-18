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
    public async Task Diagnostic_fires_when_interpolated_string_literal_text_contains_sensitive_identifier()
    {
        var source = """
            using Microsoft.Extensions.Logging;
            namespace ZeeKayDa.Auth.Services;
            class MyService
            {
                void DoWork()
                {
                    ILogger<object> logger = null!;
                    string value = "x";
                    logger.LogInformation($"client_secret={value}");
                }
            }
            """;

        var diagnostics = await GetDiagnosticsAsync(source);

        diagnostics.Should().ContainSingle()
            .Which.Id.Should().Be(InterpolatedStringLogAnalyzer.DiagnosticId);
    }

    [Fact]
    public async Task Diagnostic_fires_when_interpolated_string_hole_references_sensitive_identifier()
    {
        var source = """
            using Microsoft.Extensions.Logging;
            namespace ZeeKayDa.Auth.Services;
            class MyService
            {
                void DoWork()
                {
                    ILogger<object> logger = null!;
                    string secret = "x";
                    logger.LogInformation($"value={secret}");
                }
            }
            """;

        var diagnostics = await GetDiagnosticsAsync(source);

        diagnostics.Should().ContainSingle()
            .Which.Id.Should().Be(InterpolatedStringLogAnalyzer.DiagnosticId);
    }

    [Fact]
    public async Task Diagnostic_fires_on_representative_test_case()
    {
        var source = """
            using Microsoft.Extensions.Logging;
            namespace ZeeKayDa.Auth.Services;
            class MyService
            {
                void DoWork()
                {
                    ILogger<object> logger = null!;
                    string secret = "x";
                    logger.LogInformation($"client_secret={secret}");
                }
            }
            """;

        var diagnostics = await GetDiagnosticsAsync(source);

        diagnostics.Should().ContainSingle()
            .Which.Id.Should().Be(InterpolatedStringLogAnalyzer.DiagnosticId);
    }

    // ── No diagnostic ─────────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task No_diagnostic_for_structured_log_with_non_sensitive_key()
    {
        var source = """
            using Microsoft.Extensions.Logging;
            namespace ZeeKayDa.Auth.Services;
            class MyService
            {
                void DoWork()
                {
                    ILogger<object> logger = null!;
                    string issuer = "https://example.com";
                    logger.LogInformation("Issuer: {Issuer}", issuer);
                }
            }
            """;

        var diagnostics = await GetDiagnosticsAsync(source);

        diagnostics.Should().BeEmpty();
    }

    [Fact]
    public async Task No_diagnostic_for_interpolated_string_without_sensitive_identifier()
    {
        var source = """
            using Microsoft.Extensions.Logging;
            namespace ZeeKayDa.Auth.Services;
            class MyService
            {
                void DoWork()
                {
                    ILogger<object> logger = null!;
                    string host = "localhost";
                    int port = 5000;
                    logger.LogInformation($"Starting on {host}:{port}");
                }
            }
            """;

        var diagnostics = await GetDiagnosticsAsync(source);

        diagnostics.Should().BeEmpty();
    }

    [Fact]
    public async Task No_diagnostic_for_interpolated_string_in_non_ZeeKayDa_namespace()
    {
        var source = """
            using Microsoft.Extensions.Logging;
            namespace MyApp.Services;
            class MyService
            {
                void DoWork()
                {
                    ILogger<object> logger = null!;
                    string secret = "x";
                    logger.LogInformation($"client_secret={secret}");
                }
            }
            """;

        var diagnostics = await GetDiagnosticsAsync(source);

        diagnostics.Should().BeEmpty();
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
