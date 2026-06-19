using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;
using ZeeKayDa.Auth;
using ZeeKayDa.Auth.AspNetCore;
using ZeeKayDa.Auth.Clients;
using ZeeKayDa.Auth.Configuration;
using ZeeKayDa.Auth.Scopes;

namespace ZeeKayDa.Auth.AspNetCore.Tests.Extensions;

public sealed class ZeeKayDaAuthServiceCollectionExtensionsTests
{
    [Fact]
    public void AddZeeKayDaAuth_always_registers_CompositeClientSecretHasher()
    {
        // Verify the descriptor is always present so users get a clear "missing hasher"
        // error on first use rather than a generic "service not registered" DI failure.
        var services = new ServiceCollection();

        services.AddZeeKayDaAuth(options => options.Issuer = "https://auth.example.com");

        services.Should().Contain(sd => sd.ServiceType == typeof(CompositeClientSecretHasher));
    }

    // ── IClientSecretFactory DI wiring (AC1–AC4, issue #135) ─────────────────────────────────────

    [Fact]
    public void AddZeeKayDaAuth_registers_IClientSecretFactory_descriptor()
    {
        // AC1: the service descriptor for IClientSecretFactory must be present.
        var services = new ServiceCollection();

        services.AddZeeKayDaAuth(options => options.Issuer = "https://auth.example.com");

        services.Should().Contain(sd => sd.ServiceType == typeof(IClientSecretFactory));
    }

    [Fact]
    public void AddZeeKayDaAuth_IClientSecretFactory_is_resolvable_from_container()
    {
        // AC1: IClientSecretFactory must resolve without throwing.
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddZeeKayDaAuth(options => options.Issuer = "https://auth.example.com");
        using var provider = services.BuildServiceProvider();

        var factory = provider.GetService<IClientSecretFactory>();

        factory.Should().NotBeNull();
    }

    [Fact]
    public void AddZeeKayDaAuth_IClientSecretFactory_is_same_instance_as_CompositeClientSecretHasher()
    {
        // AC2: the IClientSecretFactory registration must be an alias for the already-constructed
        // CompositeClientSecretHasher singleton — same object reference, not a second instance.
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddZeeKayDaAuth(options => options.Issuer = "https://auth.example.com");
        using var provider = services.BuildServiceProvider();

        var factory = provider.GetRequiredService<IClientSecretFactory>();
        var composite = provider.GetRequiredService<CompositeClientSecretHasher>();

        factory.Should().BeSameAs(composite);
    }

    [Fact]
    public void AddZeeKayDaAuth_IClientSecretFactory_Create_returns_IClientSecret()
    {
        // AC3: IClientSecretFactory.Create must delegate to the default hasher and return
        // a valid IClientSecret, reachable through the interface (not the concrete type).
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddZeeKayDaAuth(options => options.Issuer = "https://auth.example.com");
        using var provider = services.BuildServiceProvider();

        var factory = provider.GetRequiredService<IClientSecretFactory>();

        var secret = factory.Create("s3cr3t-v4lu3");

        secret.Should().NotBeNull();
        secret.Should().BeAssignableTo<IClientSecret>();
    }

    [Fact]
    public void AddZeeKayDaAuth_does_not_add_IClientSecretFactory_descriptor_when_one_is_already_registered()
    {
        // AC4: TryAddSingleton is idempotent — if a caller pre-registers IClientSecretFactory
        // before AddZeeKayDaAuth runs, the existing descriptor must win and no second descriptor
        // is added. This is the same pattern used for IScopeRepository.
        var services = new ServiceCollection();
        var preRegistered = new FakeClientSecretFactory();
        services.AddSingleton<IClientSecretFactory>(preRegistered);

        services.AddZeeKayDaAuth(options => options.Issuer = "https://auth.example.com");

        services.Count(sd => sd.ServiceType == typeof(IClientSecretFactory))
            .Should().Be(1, "TryAddSingleton must not add a second descriptor");
    }

    [Fact]
    public void AddZeeKayDaAuth_does_not_override_pre_registered_IClientSecretFactory()
    {
        // AC4 (runtime): a pre-registered IClientSecretFactory must survive AddZeeKayDaAuth.
        // This verifies TryAddSingleton semantics — the first registration always wins.
        var services = new ServiceCollection();
        services.AddLogging();
        var preRegistered = new FakeClientSecretFactory();
        services.AddSingleton<IClientSecretFactory>(preRegistered);

        services.AddZeeKayDaAuth(options => options.Issuer = "https://auth.example.com");
        using var provider = services.BuildServiceProvider();

        var resolved = provider.GetRequiredService<IClientSecretFactory>();

        resolved.Should().BeSameAs(preRegistered,
            "TryAddSingleton must not replace the pre-registered IClientSecretFactory");
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void AddZeeKayDaAuth_IClientSecretFactory_Create_throws_on_invalid_plaintext(string? plaintext)
    {
        // AC3 (negative): IClientSecretFactory.Create must reject null, empty, and whitespace
        // plaintext — as documented in the interface's XML doc.
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddZeeKayDaAuth(options => options.Issuer = "https://auth.example.com");
        using var provider = services.BuildServiceProvider();

        var factory = provider.GetRequiredService<IClientSecretFactory>();

        var act = () => factory.Create(plaintext!);

        act.Should().Throw<ArgumentException>();
    }

    [Fact]
    public void AddZeeKayDaAuth_throws_ArgumentNullException_if_services_is_null()
    {
        var act = () => ((IServiceCollection)null!).AddZeeKayDaAuth(_ => { });

        act.Should().Throw<ArgumentNullException>().WithParameterName("services");
    }

    [Fact]
    public void AddZeeKayDaAuth_throws_ArgumentNullException_if_configure_is_null()
    {
        var act = () => new ServiceCollection().AddZeeKayDaAuth(null!);

        act.Should().Throw<ArgumentNullException>().WithParameterName("configure");
    }

    [Fact]
    public async Task AddZeeKayDaAuth_registers_InMemoryScopeRepository_seeded_with_StandardScopes_when_no_scope_repository_is_configured()
    {
        var services = new ServiceCollection();
        services.AddZeeKayDaAuth(options => options.Issuer = "https://auth.example.com");
        using var serviceProvider = services.BuildServiceProvider();

        var repository = serviceProvider.GetRequiredService<IScopeRepository>();
        var scopes = await repository.GetScopesAsync(TestContext.Current.CancellationToken);

        repository.Should().BeOfType<InMemoryScopeRepository>();
        scopes.Select(scope => scope.Name).Should().Equal(StandardScopes.All.Select(scope => scope.Name));
    }

    [Fact]
    public async Task AddZeeKayDaAuth_does_not_override_pre_registered_IScopeRepository()
    {
        var services = new ServiceCollection();
        var preRegisteredRepository = new InMemoryScopeRepository([StandardScopes.OpenId]);

        services.AddSingleton<IScopeRepository>(preRegisteredRepository);
        services.AddZeeKayDaAuth(options => options.Issuer = "https://auth.example.com");
        using var serviceProvider = services.BuildServiceProvider();

        var resolvedRepository = serviceProvider.GetRequiredService<IScopeRepository>();
        var scopes = await resolvedRepository.GetScopesAsync(TestContext.Current.CancellationToken);

        resolvedRepository.Should().BeSameAs(preRegisteredRepository);
        scopes.Select(scope => scope.Name).Should().Equal(StandardScopes.OpenId.Name);
    }

    [Fact]
    public void AddZeeKayDaAuth_registers_Pbkdf2ClientSecretHasher_as_IClientSecretHasher_by_default()
    {
        var services = new ServiceCollection();
        services.AddLogging();

        services.AddZeeKayDaAuth(options => options.Issuer = "https://auth.example.com");

        services.Should().Contain(sd =>
            sd.ServiceType == typeof(IClientSecretHasher) &&
            sd.ImplementationType == typeof(Pbkdf2ClientSecretHasher));
    }

    [Fact]
    public void AddZeeKayDaAuth_records_Pbkdf2ClientSecretHasher_registration_in_options()
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddZeeKayDaAuth(options => options.Issuer = "https://auth.example.com");
        using var provider = services.BuildServiceProvider();

        var opts = provider.GetRequiredService<IOptions<ClientSecretHasherRegistrationOptions>>().Value;

        opts.Registrations.Should().ContainSingle(r =>
            r.HasherType == typeof(Pbkdf2ClientSecretHasher) && r.IsDefault);
    }

    [Fact]
    public void AddZeeKayDaAuth_always_registers_ExceptionSanitizingDisabledWarningService_as_IHostedService()
    {
        // The warning service reads the flag at startup and emits a warning only when the flag
        // is set. It is always registered (unconditionally) so no additional method call is needed.
        var services = new ServiceCollection();

        services.AddZeeKayDaAuth(options => options.Issuer = "https://auth.example.com");

        services.Should().Contain(sd =>
            sd.ServiceType == typeof(IHostedService) &&
            sd.ImplementationType == typeof(ExceptionSanitizingDisabledWarningService));
    }

    [Fact]
    public void AddZeeKayDaAuth_binds_DisableExceptionSanitizing_from_configuration()
    {
        // Verify the documented appsettings.Development.json path actually works — i.e., that
        // the JSON key "ZeeKayDaAuth:Logging:DisableExceptionSanitizing" binds to the correct
        // property on AuthorizationServerOptions.
        var json = """{"ZeeKayDaAuth":{"Logging":{"DisableExceptionSanitizing":true}}}""";
        var jsonBytes = System.Text.Encoding.UTF8.GetBytes(json);
        using var jsonStream = new System.IO.MemoryStream(jsonBytes);
        var configuration = new ConfigurationBuilder()
            .AddJsonStream(jsonStream)
            .Build();

        var services = new ServiceCollection();
        services.AddSingleton<IConfiguration>(configuration);
        services
            .AddOptions<AuthorizationServerOptions>()
            .Bind(configuration.GetSection("ZeeKayDaAuth"));

        using var provider = services.BuildServiceProvider();
        var opts = provider.GetRequiredService<IOptions<AuthorizationServerOptions>>().Value;

        opts.Logging.DisableExceptionSanitizing.Should().BeTrue();
    }

    // ── Test doubles ─────────────────────────────────────────────────────────────────────────────

    /// <summary>
    /// Stand-in IClientSecretFactory used to verify pre-registration is not overwritten
    /// by TryAddSingleton inside AddZeeKayDaAuth.
    /// </summary>
    private sealed class FakeClientSecretFactory : IClientSecretFactory
    {
        public IClientSecret Create(string plaintext) => throw new NotImplementedException();
    }
}
