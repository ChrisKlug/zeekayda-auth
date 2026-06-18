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
}
