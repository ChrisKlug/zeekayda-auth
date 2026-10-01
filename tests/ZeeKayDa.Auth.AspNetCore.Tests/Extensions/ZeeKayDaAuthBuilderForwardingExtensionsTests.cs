using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using ZeeKayDa.Auth.Claims;
using ZeeKayDa.Auth.Clients;
using ZeeKayDa.Auth.Configuration;
using ZeeKayDa.Auth.Stores;
using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.AspNetCore.Tests.Extensions;

/// <summary>
/// A chain started by <c>AddZeeKayDaAuth</c> stays a <see cref="ZeeKayDaAuthBuilder"/> through the
/// core extensions, so an HTTP-only extension can follow any of them.
/// </summary>
public sealed class ZeeKayDaAuthBuilderForwardingExtensionsTests
{
    [Fact]
    public void A_chain_from_AddZeeKayDaAuth_keeps_the_ASP_NET_Core_builder_through_every_core_extension()
    {
        var services = new ServiceCollection();

        // The declared type is the assertion: each step must return ZeeKayDaAuthBuilder for the next
        // to compile, and WithProviders exists on nothing else.
        ZeeKayDaAuthBuilder builder = services.AddZeeKayDaAuth(options => options.Issuer = "https://auth.example.com")
            .AddSigningKeySource<TestSigningKeySource>()
            .AddClaimsProvider<NoClaimsProvider>()
            .AddClientSecretHasher<TestHasher>()
            .AddAuthorizationCodeStore<InMemoryAuthorizationCodeBackingStore>()
            .AddRefreshTokenStore<InMemoryRefreshTokenBackingStore>()
            .AddInMemoryClients(_ => { })
            .AddInMemoryInteractionStore()
            .WithProviders(auth => auth.AddOAuth("acme", _ => { }));

        builder.Services.Should().BeSameAs(services);
    }

    [Fact]
    public void The_forwarding_overloads_register_what_their_core_counterparts_register()
    {
        var services = new ServiceCollection();

        services.AddZeeKayDaAuth(options => options.Issuer = "https://auth.example.com")
            .AddSigningKeySource<TestSigningKeySource>()
            .AddClaimsProvider<NoClaimsProvider>()
            .AddClientSecretHasher<TestHasher>(isDefault: true)
            .AddAuthorizationCodeStore<InMemoryAuthorizationCodeBackingStore>()
            .AddRefreshTokenStore<InMemoryRefreshTokenBackingStore>();

        services.Select(d => d.ImplementationInstance).OfType<SigningKeySourceRegistration>()
            .Should().ContainSingle().Which.SourceType.Should().Be(typeof(TestSigningKeySource));
        services.Should().Contain(d => d.ServiceType == typeof(IClaimsProvider) && d.ImplementationType == typeof(NoClaimsProvider));
        services.Should().Contain(d => d.ServiceType == typeof(IClientSecretHasher) && d.ImplementationType == typeof(TestHasher));
        HasherRegistrations(services).Should().Contain(new ClientSecretHasherRegistrationOptions.HasherRegistration(typeof(TestHasher), true));
        services.Should().Contain(d => d.ServiceType == typeof(IAuthorizationCodeBackingStore) && d.ImplementationType == typeof(InMemoryAuthorizationCodeBackingStore));
        services.Should().Contain(d => d.ServiceType == typeof(IRefreshTokenBackingStore) && d.ImplementationType == typeof(InMemoryRefreshTokenBackingStore));
    }

    // Applies the configure actions directly: two default hashers would fail the options validator,
    // and only what the overload forwarded is under test here.
    private static IList<ClientSecretHasherRegistrationOptions.HasherRegistration> HasherRegistrations(IServiceCollection services)
    {
        using var provider = services.BuildServiceProvider();
        var options = new ClientSecretHasherRegistrationOptions();
        foreach (var configure in provider.GetServices<IConfigureOptions<ClientSecretHasherRegistrationOptions>>())
            configure.Configure(options);
        return options.Registrations;
    }

    private sealed class TestSecret : IClientSecret { public IClientCredential Snapshot() => new TestSecret(); }

    private sealed class TestHasher : IClientSecretHasher
    {
        public bool CanHandle(IClientSecret secret) => secret is TestSecret;
        public bool Verify(IClientSecret stored, ReadOnlySpan<char> presented) => false;
        public IClientSecret Create(ReadOnlySpan<char> plaintext) => new TestSecret();
    }
}
