using System.Reflection;
using System.Runtime.CompilerServices;
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
    public void A_chain_from_AddZeeKayDaAuth_keeps_the_ASP_NET_Core_builder_through_every_forwarding_overload()
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

    [Fact]
    public void Every_core_extension_taking_the_core_builder_has_a_forwarding_overload()
    {
        static IEnumerable<MethodInfo> ExtensionsOn(Assembly assembly, Type builderType) =>
            assembly.GetExportedTypes()
                .Where(type => type.IsAbstract && type.IsSealed)
                .SelectMany(type => type.GetMethods(BindingFlags.Public | BindingFlags.Static))
                .Where(method => method.IsDefined(typeof(ExtensionAttribute), false)
                    && method.GetParameters()[0].ParameterType == builderType);

        static string Shape(MethodInfo method) =>
            $"{method.Name}`{method.GetGenericArguments().Length}(" + string.Join(", ", method.GetParameters().Skip(1)
                .Select(parameter => parameter.ParameterType.IsGenericParameter
                    ? $"!!{parameter.ParameterType.GenericParameterPosition}"
                    : parameter.ParameterType.FullName)) + ")";

        var core = ExtensionsOn(typeof(ZeeKayDaAuthCoreBuilder).Assembly, typeof(ZeeKayDaAuthCoreBuilder)).Select(Shape);
        var forwarded = ExtensionsOn(typeof(ZeeKayDaAuthBuilder).Assembly, typeof(ZeeKayDaAuthBuilder))
            .Where(method => method.ReturnType == typeof(ZeeKayDaAuthBuilder))
            .Select(Shape);

        core.Should().NotBeEmpty().And.BeSubsetOf(forwarded);
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

    private static readonly ClientSecret TestSecret = new("$test-secret$x");

    private sealed class TestHasher : IClientSecretHasher
    {
        public IReadOnlySet<string> AlgorithmIds { get; } = new HashSet<string> { "test-secret" };
        public bool Verify(ClientSecret stored, ReadOnlySpan<char> presented) => false;
        public ClientSecret Create(ReadOnlySpan<char> plaintext) => TestSecret;
    }
}
