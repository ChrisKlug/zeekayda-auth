using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;
using ZeeKayDa.Auth;
using ZeeKayDa.Auth.Authorization;
using ZeeKayDa.Auth.Claims;
using ZeeKayDa.Auth.Clients;
using ZeeKayDa.Auth.Configuration;
using ZeeKayDa.Auth.Discovery;
using ZeeKayDa.Auth.Logging;
using ZeeKayDa.Auth.Scopes;
using ZeeKayDa.Auth.StartupVerification;
using ZeeKayDa.Auth.Stores;
using ZeeKayDa.Auth.Tokens;

namespace Microsoft.Extensions.DependencyInjection;

/// <summary>
/// Extension methods for <see cref="IServiceCollection"/> to register the ZeeKayDa.Auth
/// authorization server without its HTTP surface.
/// </summary>
public static class ZeeKayDaAuthCoreServiceCollectionExtensions
{
    /// <summary>
    /// Registers everything in ZeeKayDa.Auth that does not need an HTTP request: the validated
    /// server options, clients, scopes, stores, token issuance, and every startup check on them.
    /// </summary>
    /// <param name="services">The service collection to add services to.</param>
    /// <param name="configure">
    /// A delegate used to configure <see cref="AuthorizationServerOptions"/>. At minimum,
    /// <see cref="AuthorizationServerOptions.Issuer"/> must be set.
    /// </param>
    /// <returns>
    /// A <see cref="ZeeKayDaAuthCoreBuilder"/> that can be used to register optional features.
    /// </returns>
    /// <exception cref="ArgumentNullException">
    /// Thrown when <paramref name="services"/> or <paramref name="configure"/> is
    /// <see langword="null"/>.
    /// </exception>
    /// <remarks>
    /// <c>AddZeeKayDaAuth()</c> in <c>ZeeKayDa.Auth.AspNetCore</c> calls this and adds the HTTP surface;
    /// call it directly only for a host that does not serve the protocol over ASP.NET Core. Client
    /// authentication lives in that layer, so only public clients work without it. A repeated call adds
    /// its <paramref name="configure"/> delegate and registers nothing twice.
    /// </remarks>
    public static ZeeKayDaAuthCoreBuilder AddZeeKayDaAuthCore(
        this IServiceCollection services,
        Action<AuthorizationServerOptions> configure)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(configure);

        services
            .AddZeeKayDaOptions<AuthorizationServerOptions>()
            .Configure(configure);

        // Freezes every options collection before validation runs.
        services.TryAddEnumerable(
            ServiceDescriptor.Singleton<
                IPostConfigureOptions<AuthorizationServerOptions>,
                AuthorizationServerOptionsPostConfigurer>());

        services.TryAddEnumerable(
            ServiceDescriptor.Singleton<
                IValidateOptions<AuthorizationServerOptions>,
                AuthorizationServerOptionsValidator>());

        services.TryAddSingleton(typeof(SanitizingLogger<>), typeof(RegisteredSanitizingLogger<>));

        // The framework's token stores encrypt what they save.
        services.AddDataProtection();
        services.TryAddEnumerable(
            ServiceDescriptor.Scoped<IStartupVerifier, DataProtectionKeyRepositoryVerifier>());
        services.TryAddSingleton<TimeProvider>(TimeProvider.System);

        AddStartupVerification(services);
        AddClientServices(services);
        AddScopeServices(services);

        services.AddDefaultTokenIssuers();
        services.TryAddSingleton<IdTokenHintValidator>();
        services.TryAddSingleton<AccessTokenValidator>();

        // Always present, so a backing store registered straight on the service collection works too.
        services.TryAddSingleton<AuthorizationCodeStore>();
        services.TryAddSingleton<RefreshTokenStore>();

        services.TryAddSingleton<IDiscoveryDocumentProvider, DiscoveryDocumentProvider>();
        services.TryAddSingleton<AuthorizeRequestValidator>();

        // Keeps a repeated call from throwing on the hasher's one-registration-per-type rule.
        var builder = new ZeeKayDaAuthCoreBuilder(services);
        if (!services.Any(descriptor => descriptor.ImplementationType == typeof(Pbkdf2ClientSecretHasher)))
            builder.AddClientSecretHasher<Pbkdf2ClientSecretHasher>();
        services.TryAddEnumerable(
            ServiceDescriptor.Singleton<
                IValidateOptions<Pbkdf2ClientSecretHasherOptions>,
                Pbkdf2ClientSecretHasherOptionsValidator>());
        services.AddZeeKayDaOptions<Pbkdf2ClientSecretHasherOptions>();
        return builder;
    }

    /// <summary>Registers the startup-verification runner and every check that does not need HTTP.</summary>
    private static void AddStartupVerification(IServiceCollection services)
    {
        services.TryAddEnumerable(
            ServiceDescriptor.Singleton<IHostedService, StartupVerificationHostedService>());

        // Keeps the collection reference, so it sees registrations a host adds after this call too.
        services.TryAddSingleton(_ => new ServiceLifetimeScanner(services));

        services.TryAddEnumerable(
            ServiceDescriptor.Scoped<IStartupVerifier, HttpLoopbackIssuerVerifier>());
        services.TryAddEnumerable(
            ServiceDescriptor.Scoped<IStartupVerifier, HttpLoopbackCorsOriginsVerifier>());
        services.TryAddEnumerable(
            ServiceDescriptor.Scoped<IStartupVerifier, ExceptionSanitizingDisabledVerifier>());
        services.TryAddEnumerable(
            ServiceDescriptor.Scoped<IStartupVerifier, AbsoluteFamilyLifetimeUnboundedVerifier>());
        services.TryAddEnumerable(
            ServiceDescriptor.Scoped<IStartupVerifier, TokenLifetimeCeilingVerifier>());
        services.TryAddEnumerable(
            ServiceDescriptor.Scoped<IStartupVerifier, TokenStorePresenceVerifier>());

        services.TryAddEnumerable(
            ServiceDescriptor.Scoped<IStartupVerifier, SigningKeyRingPresenceVerifier>());

        // An activator: without IServiceProviderIsService it resolves the host's claims provider to prove it exists.
        services.TryAddEnumerable(
            ServiceDescriptor.Scoped<IStartupActivator, ClaimsProviderPresenceActivator>());

        services.TryAddEnumerable(
            ServiceDescriptor.Scoped<IStartupVerifier, WrappedRepositoryLifetimeVerifier>());
    }

    /// <summary>Registers client-secret hashing, registration validation and the validating client resolver.</summary>
    private static void AddClientServices(IServiceCollection services)
    {
        // Unconditional, so a missing IClientSecretHasher gets a clear error rather than a DI failure.
        services.TryAddSingleton<ClientSecretHasherRegistry>();
        services.TryAddEnumerable(
            ServiceDescriptor.Scoped<IStartupActivator, ClientSecretHasherActivator>());
        // Built here because its constructor is internal; replaced rather than tried, as the framework is its only supplier.
        services.RemoveAll<ClientSecrets>();
        services.AddSingleton(sp => new ClientSecrets(
            sp.GetRequiredService<ClientSecretHasherRegistry>(),
            sp.GetRequiredService<SanitizingLogger<ClientSecrets>>()));

        // Without the HTTP layer there is no client authenticator, so only 'none'; AddZeeKayDaAuth replaces it.
        services.TryAddSingleton(sp => new AdvertisedAuthMethods(
            [], sp.GetRequiredService<IOptions<AuthorizationServerOptions>>().Value.TokenEndpoint.AdvertisedAuthMethods));
        services.TryAddEnumerable(
            ServiceDescriptor.Scoped<IStartupActivator, AdvertisedAuthMethodsActivator>());

        // Built here because its constructor is internal; replaced rather than tried, as the framework is its only supplier.
        services.RemoveAll<ClientRegistrationValidator>();
        services.AddSingleton(sp => new ClientRegistrationValidator(
            sp.GetRequiredService<IOptions<AuthorizationServerOptions>>(),
            sp.GetRequiredService<AdvertisedAuthMethods>(),
            sp.GetRequiredService<ClientSecretHasherRegistry>(),
            sp.GetRequiredService<SanitizingLogger<ClientRegistrationValidator>>(),
            sp.GetService<SigningKeyRing>()));

        services.TryAddSingleton(sp => new ValidatedClientResolver(
            sp.GetRequiredService<IClientRepository>(),
            sp.GetRequiredService<ClientRegistrationValidator>().Validate,
            sp.GetRequiredService<SanitizingLogger<ValidatedClientResolver>>()));

        services.TryAddEnumerable(
            ServiceDescriptor.Scoped<IStartupVerifier, ClientRepositoryPresenceVerifier>());

        services.TryAddEnumerable(
            ServiceDescriptor.Scoped<IStartupActivator, ClientRepositoryActivator>());
    }

    /// <summary>Registers the default scope repository and the validated scope catalog.</summary>
    private static void AddScopeServices(IServiceCollection services)
    {
        services.TryAddSingleton<IScopeRepository>(new InMemoryScopeRepository(StandardScopes.All));

        // The only path to a scope definition, so a custom repository is validated on every read.
        services.TryAddSingleton<ValidatedScopeCatalog>();

        // Not IValidateOptions: the openid-scope check awaits the host's repository.
        services.TryAddEnumerable(
            ServiceDescriptor.Scoped<IStartupActivator, ScopePresenceActivator>());
    }
}
