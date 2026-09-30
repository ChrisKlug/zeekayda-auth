using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using ZeeKayDa.Auth;
using ZeeKayDa.Auth.Logging;
using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.Tests.Extensions;

public sealed class ZeeKayDaAuthCoreServiceCollectionExtensionsTests
{
    private static void ValidIssuer(AuthorizationServerOptions options) => options.Issuer = MinimalCoreHost.Issuer;

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
    public void AddZeeKayDaAuthCore_registers_ISanitizingLogger_as_SecretSanitizingLogger()
    {
        var services = ServicesWithLogging();

        services.AddZeeKayDaAuthCore(ValidIssuer);

        using var provider = services.BuildServiceProvider();
        var resolved = provider.GetRequiredService<ISanitizingLogger<object>>();

        resolved.Should().BeOfType<SecretSanitizingLogger<object>>();
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
        services.AddMinimalZeeKayDaAuthCore().AddInMemoryDevelopmentSigning();

        await using var provider = services.BuildServiceProvider();
        var act = () => StartAsync(provider);

        await act.Should().NotThrowAsync();
    }

    [Fact]
    public async Task A_core_only_host_validates_the_server_options_at_startup()
    {
        var services = ServicesWithLogging();
        services.AddMinimalZeeKayDaAuthCore().AddInMemoryDevelopmentSigning();
        services.Configure<AuthorizationServerOptions>(options => options.Issuer = "not-a-uri");

        await using var provider = services.BuildServiceProvider();
        var act = () => StartAsync(provider);

        (await act.Should().ThrowAsync<ZeeKayDaConfigurationException>())
            .Which.AggregatedFailures.Should().Contain(failure => failure.Code == "configuration.issuer.invalid");
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

    [Fact]
    public void AddZeeKayDaAuthCore_registers_the_sanitizing_logger_gate_first_and_the_options_gate_second()
    {
        var services = new ServiceCollection();

        services.AddZeeKayDaAuthCore(ValidIssuer);

        services.Where(descriptor => descriptor.ServiceType == typeof(IStartupVerificationGate))
            .Select(descriptor => descriptor.ImplementationType)
            .Should().Equal(typeof(SanitizingLoggerRegistrationGate), typeof(ValidatedOptionsGate));
    }
}
