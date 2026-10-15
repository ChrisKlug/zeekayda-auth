using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Primitives;
using ZeeKayDa.Auth;
using ZeeKayDa.Auth.AspNetCore;
using ZeeKayDa.Auth.AspNetCore.ClientAuthentication;
using ZeeKayDa.Auth.Clients;
using ZeeKayDa.Auth.Configuration;
using ZeeKayDa.Auth.Logging;
using ZeeKayDa.Auth.Scopes;
using ZeeKayDa.Auth.StartupVerification;
using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.AspNetCore.Tests.Extensions;

public sealed class ZeeKayDaAuthServiceCollectionExtensionsTests
{
    [Fact]
    public async Task AddZeeKayDaAuth_called_twice_starts_with_each_cookie_scheme_registered_once()
    {
        using var host = new EndpointHost(configureBuilder: builder =>
            builder.Services.AddZeeKayDaAuth(options => options.ClockSkewTolerance = TimeSpan.FromSeconds(10)));

        await host.EnsureStartedAsync();

        var schemes = await host.Resolve<IAuthenticationSchemeProvider>().GetAllSchemesAsync();
        schemes.Select(scheme => scheme.Name).Should().OnlyHaveUniqueItems().And.Contain(["zkd.session", "zkd.external"]);
        host.Resolve<IOptions<AuthorizationServerOptions>>().Value.ClockSkewTolerance.Should().Be(TimeSpan.FromSeconds(10));
    }

    [Theory]
    [InlineData(typeof(HttpLoopbackIssuerVerifier))]
    [InlineData(typeof(HttpLoopbackCorsOriginsVerifier))]
    [InlineData(typeof(ExceptionSanitizingDisabledVerifier))]
    public void AddZeeKayDaAuth_always_registers_a_verifier_for_each_Development_switch(Type verifierType)
    {
        // Each verifier reads its flag at startup and reports only when the flag is set, so it is
        // registered unconditionally and no additional method call is needed.
        var services = new ServiceCollection();

        services.AddZeeKayDaAuth(options => options.Issuer = "https://auth.example.com");

        services.Should().Contain(sd =>
            sd.ServiceType == typeof(IStartupVerifier) &&
            sd.ImplementationType == verifierType);
    }

    [Theory]
    [InlineData(nameof(TokenKind.AccessToken))]
    [InlineData(nameof(TokenKind.IdToken))]
    public void AddZeeKayDaAuth_registers_JwtTokenIssuer_for_each_TokenKind(string kindName)
    {
        var kind = Enum.Parse<TokenKind>(kindName);
        var services = new ServiceCollection();

        services.AddZeeKayDaAuth(options => options.Issuer = "https://auth.example.com");

        services.Should().ContainSingle(sd =>
            sd.ServiceType == typeof(ITokenIssuer) &&
            Equals(sd.ServiceKey, kind) &&
            sd.KeyedImplementationType == typeof(JwtTokenIssuer));
    }

    [Fact]
    public async Task ValidatedClientResolver_serves_public_client_with_credentials_as_unknown()
    {
        // The none path trusts IsPublic because the resolver enforces public <=> no credentials.
        var corrupt = Client.CreatePublic("public-client", ["https://app.example.com/cb"], [], ["openid"])
            with
        { Secrets = [Pbkdf2ClientSecretHasher.Format(600_000, new byte[16], new byte[32])] };
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddSingleton<IClientRepository>(new SingleClientRepository(corrupt));
        services.AddZeeKayDaAuth(options =>
        {
            options.Issuer = "https://auth.example.com";
        });
        using var provider = services.BuildServiceProvider();

        var served = await provider.GetRequiredService<ValidatedClientResolver>()
            .FindClientWithCredentialsAsync("public-client", TestContext.Current.CancellationToken);

        served.Should().BeNull();
    }

    [Fact]
    public void A_custom_repository_can_inject_the_framework_rules_to_check_a_client_before_saving()
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddSingleton<IClientRepository>(new SingleClientRepository(
            Client.CreatePublic("public-client", ["https://app.example.com/cb"], [], ["openid"])));
        services.AddZeeKayDaAuth(options => options.Issuer = "https://auth.example.com");
        using var provider = services.BuildServiceProvider();
        var invalid = Client.CreatePublic("spa", ["https://app.example.com/cb#fragment"], [], ["openid"]);

        var failures = provider.GetRequiredService<ClientRegistrationValidator>().Validate(invalid);

        failures.Should().Contain(f => f.Code == "client.redirect_uri.fragment");
    }

    private sealed class SingleClientRepository(IClientWithCredentials client) : IClientRepository
    {
        public Task<IClientWithCredentials?> FindByClientIdAsync(string clientId, CancellationToken cancellationToken = default)
            => Task.FromResult(clientId == client.ClientId ? client : null);
    }

    // ── ClientSecrets DI wiring (AC1–AC4, issue #135) ─────────────────────────────────────

    [Fact]
    public void AddZeeKayDaAuth_ClientSecrets_is_one_singleton()
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddZeeKayDaAuth(options => options.Issuer = "https://auth.example.com");
        using var provider = services.BuildServiceProvider();

        var first = provider.GetRequiredService<ClientSecrets>();

        first.Should().BeOfType<ClientSecrets>()
            .And.BeSameAs(provider.GetRequiredService<ClientSecrets>());
    }

    [Fact]
    public void AddZeeKayDaAuth_ClientSecrets_Create_returns_a_ClientSecret()
    {
        // ClientSecrets.Create delegates to the default hasher.
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddZeeKayDaAuth(options => options.Issuer = "https://auth.example.com");
        using var provider = services.BuildServiceProvider();

        var secrets = provider.GetRequiredService<ClientSecrets>();

        var secret = secrets.Create("s3cr3t-v4lu3");

        secret.Value.Should().StartWith("$pbkdf2-sha256$");
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void AddZeeKayDaAuth_ClientSecrets_Create_throws_on_invalid_plaintext(string? plaintext)
    {
        // AC3 (negative): ClientSecrets.Create must reject null, empty, and whitespace
        // plaintext — as documented in the interface's XML doc.
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddZeeKayDaAuth(options => options.Issuer = "https://auth.example.com");
        using var provider = services.BuildServiceProvider();

        var secrets = provider.GetRequiredService<ClientSecrets>();

        var act = () => secrets.Create(plaintext!);

        act.Should().Throw<ArgumentException>();
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
    public void AddZeeKayDaAuth_registers_PBKDF2_unmarked_and_it_is_the_default()
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddZeeKayDaAuth(options => options.Issuer = "https://auth.example.com");
        using var provider = services.BuildServiceProvider();

        var opts = provider.GetRequiredService<IOptions<ClientSecretHasherRegistrationOptions>>().Value;

        opts.Registrations.Should().ContainSingle(r =>
            r.HasherType == typeof(Pbkdf2ClientSecretHasher) && !r.IsDefault);
        opts.DefaultHasherType.Should().Be(typeof(Pbkdf2ClientSecretHasher));
    }

    [Fact]
    public void AddZeeKayDaAuth_binds_the_Development_switches_from_configuration()
    {
        var json = """{"ZeeKayDaAuth":{"Development":{"AllowHttpLoopbackIssuer":true,"AllowHttpLoopbackCorsOrigins":true,"DisableExceptionSanitizing":true}}}""";
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

        opts.Development.AllowHttpLoopbackIssuer.Should().BeTrue();
        opts.Development.AllowHttpLoopbackCorsOrigins.Should().BeTrue();
        opts.Development.DisableExceptionSanitizing.Should().BeTrue();
    }
}
