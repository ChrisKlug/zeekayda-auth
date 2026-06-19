using System.Collections.Immutable;
using System.Linq;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.Diagnostics;
using ZeeKayDa.Auth.Analyzers;

namespace ZeeKayDa.Auth.Analyzers.Tests;

public sealed class ClientRepositoryValidatorAnalyzerTests
{
    // ── Diagnostic fires ──────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task Diagnostic_fires_when_IClientRepository_implementation_never_references_validator()
    {
        var source = """
            using System.Threading;
            using System.Threading.Tasks;
            using ZeeKayDa.Auth.Clients;
            namespace MyCompany.Auth
            {
                public sealed class MyClientRepository : IClientRepository
                {
                    public ValueTask<IClientRegistration?> FindByClientIdAsync(string clientId, CancellationToken cancellationToken = default)
                        => ValueTask.FromResult<IClientRegistration?>(null);
                }
            }
            """;

        var diagnostics = await GetDiagnosticsAsync(source);

        diagnostics.Should().ContainSingle()
            .Which.Id.Should().Be(ClientRepositoryValidatorAnalyzer.DiagnosticId);
    }

    [Fact]
    public async Task Diagnostic_fires_on_record_implementation()
    {
        var source = """
            using System.Threading;
            using System.Threading.Tasks;
            using ZeeKayDa.Auth.Clients;
            namespace MyCompany.Auth
            {
                public sealed record MyClientRepository : IClientRepository
                {
                    public ValueTask<IClientRegistration?> FindByClientIdAsync(string clientId, CancellationToken cancellationToken = default)
                        => ValueTask.FromResult<IClientRegistration?>(null);
                }
            }
            """;

        var diagnostics = await GetDiagnosticsAsync(source);

        diagnostics.Should().ContainSingle()
            .Which.Id.Should().Be(ClientRepositoryValidatorAnalyzer.DiagnosticId);
    }

    [Fact]
    public async Task Diagnostic_fires_on_struct_implementation()
    {
        var source = """
            using System.Threading;
            using System.Threading.Tasks;
            using ZeeKayDa.Auth.Clients;
            namespace MyCompany.Auth
            {
                public struct MyClientRepository : IClientRepository
                {
                    public ValueTask<IClientRegistration?> FindByClientIdAsync(string clientId, CancellationToken cancellationToken = default)
                        => ValueTask.FromResult<IClientRegistration?>(null);
                }
            }
            """;

        var diagnostics = await GetDiagnosticsAsync(source);

        diagnostics.Should().ContainSingle()
            .Which.Id.Should().Be(ClientRepositoryValidatorAnalyzer.DiagnosticId);
    }

    [Fact]
    public async Task Diagnostic_fires_on_record_struct_implementation()
    {
        var source = """
            using System.Threading;
            using System.Threading.Tasks;
            using ZeeKayDa.Auth.Clients;
            namespace MyCompany.Auth
            {
                public record struct MyClientRepository : IClientRepository
                {
                    public ValueTask<IClientRegistration?> FindByClientIdAsync(string clientId, CancellationToken cancellationToken = default)
                        => ValueTask.FromResult<IClientRegistration?>(null);
                }
            }
            """;

        var diagnostics = await GetDiagnosticsAsync(source);

        diagnostics.Should().ContainSingle()
            .Which.Id.Should().Be(ClientRepositoryValidatorAnalyzer.DiagnosticId);
    }

    // ── No diagnostic ─────────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task No_diagnostic_when_validator_is_injected_in_constructor()
    {
        var source = """
            using System.Threading;
            using System.Threading.Tasks;
            using ZeeKayDa.Auth.Clients;
            namespace MyCompany.Auth
            {
                public sealed class MyClientRepository : IClientRepository
                {
                    private readonly IClientRegistrationValidator _validator;
                    public MyClientRepository(IClientRegistrationValidator validator) { _validator = validator; }
                    public ValueTask<IClientRegistration?> FindByClientIdAsync(string clientId, CancellationToken cancellationToken = default)
                        => ValueTask.FromResult<IClientRegistration?>(null);
                }
            }
            """;

        var diagnostics = await GetDiagnosticsAsync(source);

        diagnostics.Should().BeEmpty();
    }

    [Fact]
    public async Task No_diagnostic_when_validator_is_stored_as_field()
    {
        var source = """
            using System.Threading;
            using System.Threading.Tasks;
            using ZeeKayDa.Auth.Clients;
            namespace MyCompany.Auth
            {
                public sealed class MyClientRepository : IClientRepository
                {
                    private IClientRegistrationValidator _validator = null!;
                    public ValueTask<IClientRegistration?> FindByClientIdAsync(string clientId, CancellationToken cancellationToken = default)
                        => ValueTask.FromResult<IClientRegistration?>(null);
                }
            }
            """;

        var diagnostics = await GetDiagnosticsAsync(source);

        diagnostics.Should().BeEmpty();
    }

    [Fact]
    public async Task No_diagnostic_when_validator_is_a_property()
    {
        var source = """
            using System.Threading;
            using System.Threading.Tasks;
            using ZeeKayDa.Auth.Clients;
            namespace MyCompany.Auth
            {
                public sealed class MyClientRepository : IClientRepository
                {
                    public IClientRegistrationValidator Validator { get; set; } = null!;
                    public ValueTask<IClientRegistration?> FindByClientIdAsync(string clientId, CancellationToken cancellationToken = default)
                        => ValueTask.FromResult<IClientRegistration?>(null);
                }
            }
            """;

        var diagnostics = await GetDiagnosticsAsync(source);

        diagnostics.Should().BeEmpty();
    }

    [Fact]
    public async Task No_diagnostic_when_validator_method_is_called()
    {
        var source = """
            using System.Threading;
            using System.Threading.Tasks;
            using ZeeKayDa.Auth.Clients;
            namespace MyCompany.Auth
            {
                public sealed class MyClientRepository : IClientRepository
                {
                    private readonly IClientRegistrationValidator _validator;
                    public MyClientRepository(IClientRegistrationValidator validator) { _validator = validator; }
                    public ValueTask<IClientRegistration?> FindByClientIdAsync(string clientId, CancellationToken cancellationToken = default)
                    {
                        IClientRegistration? reg = null;
                        if (reg is not null)
                            _validator.Validate(reg);
                        return ValueTask.FromResult<IClientRegistration?>(null);
                    }
                }
            }
            """;

        var diagnostics = await GetDiagnosticsAsync(source);

        diagnostics.Should().BeEmpty();
    }

    [Fact]
    public async Task No_diagnostic_when_validator_is_a_local_variable()
    {
        // Exercises the ILocalSymbol branch in IsOrReferencesValidator.
        // The validator is declared as a local variable inside a method — no field, property, or
        // constructor parameter is present.
        var source = """
            using System.Threading;
            using System.Threading.Tasks;
            using ZeeKayDa.Auth.Clients;
            namespace MyCompany.Auth
            {
                public sealed class MyClientRepository : IClientRepository
                {
                    private readonly System.IServiceProvider _services;
                    public MyClientRepository(System.IServiceProvider services) { _services = services; }
                    public ValueTask<IClientRegistration?> FindByClientIdAsync(string clientId, CancellationToken cancellationToken = default)
                    {
                        IClientRegistrationValidator validator = (IClientRegistrationValidator)_services.GetService(typeof(IClientRegistrationValidator))!;
                        return ValueTask.FromResult<IClientRegistration?>(null);
                    }
                }
            }
            """;

        var diagnostics = await GetDiagnosticsAsync(source);

        diagnostics.Should().BeEmpty();
    }

    [Fact]
    public async Task No_diagnostic_when_validator_type_is_referenced_in_typeof_expression()
    {
        // Exercises the INamedTypeSymbol branch in IsOrReferencesValidator.
        // The type name IClientRegistrationValidator appears only inside typeof() — no field,
        // property, parameter, or local of that type exists.
        var source = """
            using System.Threading;
            using System.Threading.Tasks;
            using ZeeKayDa.Auth.Clients;
            namespace MyCompany.Auth
            {
                public sealed class MyClientRepository : IClientRepository
                {
                    private readonly System.IServiceProvider _services;
                    public MyClientRepository(System.IServiceProvider services) { _services = services; }
                    public ValueTask<IClientRegistration?> FindByClientIdAsync(string clientId, CancellationToken cancellationToken = default)
                    {
                        var validatorType = typeof(IClientRegistrationValidator);
                        return ValueTask.FromResult<IClientRegistration?>(null);
                    }
                }
            }
            """;

        var diagnostics = await GetDiagnosticsAsync(source);

        diagnostics.Should().BeEmpty();
    }

    [Fact]
    public async Task No_diagnostic_for_in_assembly_implementation()
    {
        // Types defined in ZeeKayDa.Auth itself are exempt — they are in-framework implementations.
        var source = """
            using System.Threading;
            using System.Threading.Tasks;
            using ZeeKayDa.Auth.Clients;
            namespace ZeeKayDa.Auth.Clients
            {
                internal sealed class InAssemblyRepository : IClientRepository
                {
                    public ValueTask<IClientRegistration?> FindByClientIdAsync(string clientId, CancellationToken cancellationToken = default)
                        => ValueTask.FromResult<IClientRegistration?>(null);
                }
            }
            """;

        var diagnostics = await GetDiagnosticsAsync(source, assemblyName: "ZeeKayDa.Auth");

        diagnostics.Should().BeEmpty();
    }

    [Fact]
    public async Task No_diagnostic_for_type_that_does_not_implement_IClientRepository()
    {
        var source = """
            using System.Threading;
            using System.Threading.Tasks;
            using ZeeKayDa.Auth.Clients;
            namespace MyCompany.Auth
            {
                public sealed class SomeOtherService
                {
                    public void DoSomething() { }
                }
            }
            """;

        var diagnostics = await GetDiagnosticsAsync(source);

        diagnostics.Should().BeEmpty();
    }

    [Fact]
    public async Task Diagnostic_fires_for_out_of_assembly_impl_in_ZeeKayDa_Auth_prefixed_namespace()
    {
        // The assembly-name exemption checks the assembly name ("ZeeKayDa.Auth"), not the namespace
        // prefix. An implementation in the ZeeKayDa.Auth.Custom namespace but compiled into a
        // user assembly ("SomeUserAssembly") must still fire.
        var source = """
            using System.Threading;
            using System.Threading.Tasks;
            using ZeeKayDa.Auth.Clients;
            namespace ZeeKayDa.Auth.Custom
            {
                public sealed class MyClientRepository : IClientRepository
                {
                    public ValueTask<IClientRegistration?> FindByClientIdAsync(string clientId, CancellationToken cancellationToken = default)
                        => ValueTask.FromResult<IClientRegistration?>(null);
                }
            }
            """;

        var diagnostics = await GetDiagnosticsAsync(source);

        diagnostics.Should().ContainSingle()
            .Which.Id.Should().Be(ClientRepositoryValidatorAnalyzer.DiagnosticId);
    }

    [Fact]
    public async Task No_diagnostic_when_IClientRepository_is_implemented_transitively_via_intermediate_interface()
    {
        // AllInterfaces is transitive, so a class implementing IMyCustomRepo (which extends
        // IClientRepository) is still detected. The validator reference should suppress the diagnostic.
        var source = """
            using System.Threading;
            using System.Threading.Tasks;
            using ZeeKayDa.Auth.Clients;
            namespace MyCompany.Auth
            {
                public interface IMyCustomRepo : IClientRepository { }

                public sealed class MyClientRepository : IMyCustomRepo
                {
                    private readonly IClientRegistrationValidator _validator;
                    public MyClientRepository(IClientRegistrationValidator validator) { _validator = validator; }
                    public ValueTask<IClientRegistration?> FindByClientIdAsync(string clientId, CancellationToken cancellationToken = default)
                        => ValueTask.FromResult<IClientRegistration?>(null);
                }
            }
            """;

        var diagnostics = await GetDiagnosticsAsync(source);

        diagnostics.Should().BeEmpty();
    }

    [Fact]
    public async Task No_diagnostic_when_struct_implementation_references_validator()
    {
        var source = """
            using System.Threading;
            using System.Threading.Tasks;
            using ZeeKayDa.Auth.Clients;
            namespace MyCompany.Auth
            {
                public struct MyClientRepository : IClientRepository
                {
                    private readonly IClientRegistrationValidator _validator;
                    public MyClientRepository(IClientRegistrationValidator validator) { _validator = validator; }
                    public ValueTask<IClientRegistration?> FindByClientIdAsync(string clientId, CancellationToken cancellationToken = default)
                        => ValueTask.FromResult<IClientRegistration?>(null);
                }
            }
            """;

        var diagnostics = await GetDiagnosticsAsync(source);

        diagnostics.Should().BeEmpty();
    }

    [Fact]
    public async Task No_diagnostic_when_record_implementation_references_validator()
    {
        var source = """
            using System.Threading;
            using System.Threading.Tasks;
            using ZeeKayDa.Auth.Clients;
            namespace MyCompany.Auth
            {
                public sealed record MyClientRepository : IClientRepository
                {
                    private readonly IClientRegistrationValidator _validator;
                    public MyClientRepository(IClientRegistrationValidator validator) { _validator = validator; }
                    public ValueTask<IClientRegistration?> FindByClientIdAsync(string clientId, CancellationToken cancellationToken = default)
                        => ValueTask.FromResult<IClientRegistration?>(null);
                }
            }
            """;

        var diagnostics = await GetDiagnosticsAsync(source);

        diagnostics.Should().BeEmpty();
    }

    // ── Infrastructure ────────────────────────────────────────────────────────────────────────────

    private static async Task<ImmutableArray<Diagnostic>> GetDiagnosticsAsync(
        string source,
        string assemblyName = "SomeUserAssembly")
    {
        var references = BuildReferences();

        var compilation = CSharpCompilation.Create(
            assemblyName,
            new[] { CSharpSyntaxTree.ParseText(source) },
            references,
            new CSharpCompilationOptions(OutputKind.DynamicallyLinkedLibrary));

        var analyzers = ImmutableArray.Create<DiagnosticAnalyzer>(new ClientRepositoryValidatorAnalyzer());
        var compilationWithAnalyzers = compilation.WithAnalyzers(analyzers);
        return await compilationWithAnalyzers.GetAnalyzerDiagnosticsAsync();
    }

    private static MetadataReference[] BuildReferences()
    {
        // Collect all transitive runtime assemblies (covers System.Threading, ValueTask, etc.)
        var runtimeDir = System.IO.Path.GetDirectoryName(typeof(object).Assembly.Location)!;
        var systemAssemblies = System.IO.Directory
            .EnumerateFiles(runtimeDir, "System.*.dll")
            .Select(p => MetadataReference.CreateFromFile(p))
            .Cast<MetadataReference>()
            .ToList();

        systemAssemblies.Add(MetadataReference.CreateFromFile(typeof(object).Assembly.Location));
        systemAssemblies.Add(
            MetadataReference.CreateFromFile(
                typeof(ZeeKayDa.Auth.Clients.IClientRepository).Assembly.Location));

        return systemAssemblies.ToArray();
    }
}
