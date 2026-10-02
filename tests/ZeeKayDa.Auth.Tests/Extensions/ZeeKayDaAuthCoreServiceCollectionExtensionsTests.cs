using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using ZeeKayDa.Auth;
using ZeeKayDa.Auth.Clients;
using ZeeKayDa.Auth.Logging;
using ZeeKayDa.Auth.StartupVerification;
using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.Tests.Extensions;

public sealed class ZeeKayDaAuthCoreServiceCollectionExtensionsTests
{
    private static void ValidIssuer(AuthorizationServerOptions options) => options.Issuer = "https://issuer.test";

    private static ServiceCollection ServicesWithLogging()
    {
        var services = new ServiceCollection();
        services.AddSingleton(typeof(ILogger<>), typeof(NullLogger<>));
        return services;
    }

    private static async Task StartAsync(IServiceProvider provider)
    {
        foreach (var hostedService in provider.GetServices<IHostedService>())
            await hostedService.StartAsync(TestContext.Current.CancellationToken);
    }

    [Fact]
    public void AddZeeKayDaAuthCore_registers_SanitizingLogger_open_generic()
    {
        var services = ServicesWithLogging();

        services.AddZeeKayDaAuthCore(ValidIssuer);

        using var provider = services.BuildServiceProvider();
        var resolved = provider.GetRequiredService<SanitizingLogger<object>>();

        resolved.Should().BeOfType<RegisteredSanitizingLogger<object>>();
    }

    [Fact]
    public void AddZeeKayDaAuthCore_called_twice_registers_everything_once_and_applies_both_delegates()
    {
        var services = ServicesWithLogging();

        services.AddZeeKayDaAuthCore(ValidIssuer);
        services.AddZeeKayDaAuthCore(options => options.ClockSkewTolerance = TimeSpan.FromSeconds(10));

        services.Should().ContainSingle(descriptor => descriptor.ServiceType == typeof(SanitizingLogger<>));
        services.Should().ContainSingle(descriptor => descriptor.ImplementationType == typeof(Pbkdf2ClientSecretHasher));
        using var provider = services.BuildServiceProvider();
        var options = provider.GetRequiredService<IOptions<AuthorizationServerOptions>>().Value;
        options.Issuer.Should().Be("https://issuer.test");
        options.ClockSkewTolerance.Should().Be(TimeSpan.FromSeconds(10));
    }

    [Fact]
    public void AddZeeKayDaAuthCore_throws_ArgumentNullException_if_services_is_null()
    {
        IServiceCollection services = null!;
        var act = () => services.AddZeeKayDaAuthCore(ValidIssuer);

        act.Should().Throw<ArgumentNullException>();
    }

    [Fact]
    public void AddZeeKayDaAuthCore_throws_ArgumentNullException_if_configure_is_null()
    {
        var act = () => new ServiceCollection().AddZeeKayDaAuthCore(null!);

        act.Should().Throw<ArgumentNullException>();
    }

    [Fact]
    public async Task A_core_only_host_with_every_mandatory_seam_starts()
    {
        var services = ServicesWithLogging();
        services.AddZeeKayDaAuthCoreForTesting().AddInMemoryDevelopmentSigning();

        await using var provider = services.BuildServiceProvider();
        var act = () => StartAsync(provider);

        await act.Should().NotThrowAsync();
    }

    [Fact]
    public async Task A_core_only_host_validates_the_server_options_at_startup()
    {
        var services = ServicesWithLogging();
        services.AddZeeKayDaAuthCoreForTesting().AddInMemoryDevelopmentSigning();
        services.Configure<AuthorizationServerOptions>(options => options.Issuer = "not-a-uri");

        await using var provider = services.BuildServiceProvider();
        var act = () => StartAsync(provider);

        (await act.Should().ThrowAsync<ZeeKayDaConfigurationException>())
            .Which.AggregatedFailures.Should().Contain(failure => failure.Code == "configuration.issuer.invalid");
    }

    [Fact]
    public async Task A_hasher_whose_Create_throws_fails_startup_on_a_host_with_its_own_client_repository()
    {
        var services = ServicesWithLogging();
        services.AddZeeKayDaAuthCoreForTesting()
            .AddInMemoryDevelopmentSigning()
            .AddClientSecretHasher<VerifyOnlyHasher>();
        services.Replace(ServiceDescriptor.Singleton<IClientRepository, EmptyClientRepository>());

        await using var provider = services.BuildServiceProvider();
        var act = () => StartAsync(provider);

        (await act.Should().ThrowAsync<ZeeKayDaConfigurationException>())
            .Which.AggregatedFailures.Should().Contain(failure => failure.Code == "configuration.hashers.timing_decoy_unhandled");
    }

    private sealed class EmptyClientRepository : IClientRepository
    {
        public Task<IClientWithCredentials?> FindByClientIdAsync(string clientId, CancellationToken cancellationToken = default)
            => Task.FromResult<IClientWithCredentials?>(null);
    }

    private static readonly ClientSecret LegacySecret = new("$legacy-secret$x");

    private sealed class VerifyOnlyHasher : IClientSecretHasher
    {
        public IReadOnlySet<string> AlgorithmIds { get; } = new HashSet<string> { "legacy-secret" };
        public bool Verify(ReadOnlySpan<char> presented, ClientSecret stored) => false;
        public ClientSecret Create(ReadOnlySpan<char> plaintext) => throw new NotSupportedException();
    }

    // ── Issue #521: TokenKind-to-issuer dispatch via keyed DI ────────────────────────────────────

    private sealed class StubRing : ISigningKeyRing
    {
        public SigningKeySet Current => throw new InvalidOperationException("not initialized");

        public Task<SigningOutcome> SignAsync<TState>(
            TState state,
            Func<SigningContext, TState, ReadOnlyMemory<byte>> buildSigningInput,
            CancellationToken cancellationToken = default) => throw new InvalidOperationException("not initialized");

        Task ISigningKeyRing.EnsureInitializedAsync(CancellationToken cancellationToken) => Task.CompletedTask;

        SigningKeySet? ISigningKeyRing.CurrentOrNull => null;
    }

    private sealed class StubIssuer : ITokenIssuer
    {
        public Task<IssuedToken> IssueAsync(
            TokenIssuanceContext context, TokenPayload payload, CancellationToken cancellationToken = default)
            => Task.FromResult<IssuedToken>(new IssuedToken("stub", context is IdTokenIssuanceContext ? TokenKind.IdToken : TokenKind.AccessToken));
    }

    [Theory]
    [InlineData(TokenKind.AccessToken)]
    [InlineData(TokenKind.IdToken)]
    public void AddZeeKayDaAuthCore_registers_JwtTokenIssuer_for_each_TokenKind(TokenKind kind)
    {
        var services = ServicesWithLogging();
        services.AddSingleton<ISigningKeyRing>(new StubRing());

        services.AddZeeKayDaAuthCore(ValidIssuer);

        using var provider = services.BuildServiceProvider();
        provider.GetRequiredKeyedService<ITokenIssuer>(kind).Should().BeOfType<JwtTokenIssuer>();
    }

    [Fact]
    public void AddZeeKayDaAuthCore_keeps_a_hosts_own_issuer_registration_for_a_kind()
    {
        var services = ServicesWithLogging();
        services.AddSingleton<ISigningKeyRing>(new StubRing());
        var hostIssuer = new StubIssuer();
        services.AddKeyedSingleton<ITokenIssuer>(TokenKind.AccessToken, hostIssuer);

        services.AddZeeKayDaAuthCore(ValidIssuer);

        using var provider = services.BuildServiceProvider();
        provider.GetRequiredKeyedService<ITokenIssuer>(TokenKind.AccessToken).Should().BeSameAs(hostIssuer);
        provider.GetRequiredKeyedService<ITokenIssuer>(TokenKind.IdToken).Should().BeOfType<JwtTokenIssuer>(
            "overriding one kind must not affect the other");
    }

    // ── Issue #444: unified startup verification wiring ─────────────────────────────────────────────

    [Fact]
    public void AddZeeKayDaAuthCore_registers_StartupVerificationHostedService_as_a_hosted_service()
    {
        var services = ServicesWithLogging();

        services.AddZeeKayDaAuthCore(ValidIssuer);

        using var provider = services.BuildServiceProvider();
        provider.GetServices<IHostedService>().OfType<StartupVerificationHostedService>().Should().ContainSingle();
    }
}
