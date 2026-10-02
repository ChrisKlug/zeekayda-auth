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
    /// <c>AddZeeKayDaAuth()</c> in <c>ZeeKayDa.Auth.AspNetCore</c> calls this method and adds the
    /// endpoints, cookies, interaction and external providers on top. Call it directly only for a
    /// host that does not serve the protocol over ASP.NET Core. A repeated call adds its
    /// <paramref name="configure"/> delegate and registers nothing twice.
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
        services.TryAddSingleton<TimeProvider>(TimeProvider.System);

        AddStartupVerification(services);
        AddClientServices(services);
        AddScopeServices(services);

        services.AddDefaultTokenIssuers();
        services.TryAddSingleton<IdTokenHintValidator>();
        services.TryAddSingleton<AccessTokenValidator>();

        // The framework's own token stores, always present; a host supplies only what backs them,
        // so a backing store registered straight on the service collection works too.
        services.TryAddSingleton<AuthorizationCodeStore>();
        services.TryAddSingleton<RefreshTokenStore>();

        services.TryAddSingleton<IDiscoveryDocumentProvider, DiscoveryDocumentProvider>();
        services.TryAddSingleton<AuthorizeRequestValidator>();

        // Every other registration here is a TryAdd; this guard is what keeps a repeated call from
        // throwing on the hasher's one-registration-per-type rule.
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

    /// <summary>
    /// Registers the startup-verification runner and every check that does not need
    /// HTTP: an <see cref="IStartupVerifier"/> where the check is pure configuration, an
    /// <see cref="IStartupActivator"/> where it calls caller-supplied code or must be awaited.
    /// </summary>
    private static void AddStartupVerification(IServiceCollection services)
    {
        services.TryAddEnumerable(
            ServiceDescriptor.Singleton<IHostedService, StartupVerificationHostedService>());

        // The scanner keeps the collection reference, so the lifetime checks see registrations a
        // host adds after this call too.
        services.TryAddSingleton(_ => new ServiceLifetimeScanner(services));

        // Registered here as well as by AddSigningKeySource for coverage: StaticSigningKeyRing has
        // a public constructor, so a host can register an ISigningKeyRing itself without going
        // through AddSigningKeySource, and without this that ring would never be initialized or
        // self-tested. A silent no-op when no ring is registered at all.
        services.TryAddEnumerable(
            ServiceDescriptor.Scoped<IStartupActivator, SigningKeyRingActivator>());

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

        // Tokens are signed with the ring, so a server without one must not start.
        services.TryAddEnumerable(
            ServiceDescriptor.Scoped<IStartupVerifier, SigningKeyRingPresenceVerifier>());

        // The claims seam is mandatory with no default: a host that forgot it must not start and
        // silently issue tokens with no subject claims. An activator, since on a container without
        // IServiceProviderIsService it resolves the caller's provider to prove it is there.
        services.TryAddEnumerable(
            ServiceDescriptor.Scoped<IStartupActivator, ClaimsProviderPresenceActivator>());

        // Both wrapped repositories are held by singletons, so a host registering one as scoped
        // would have it captured.
        services.TryAddEnumerable(
            ServiceDescriptor.Scoped<IStartupVerifier, WrappedRepositoryLifetimeVerifier>());
    }

    /// <summary>
    /// Registers client-secret hashing, client registration validation, and the validating
    /// resolver every client lookup goes through.
    /// </summary>
    private static void AddClientServices(IServiceCollection services)
    {
        // Registered unconditionally so using it without any IClientSecretHasher gives a clear
        // error instead of a generic "service not registered" DI failure.
        services.TryAddSingleton<ClientSecretHasherRegistry>();
        services.TryAddEnumerable(
            ServiceDescriptor.Scoped<IStartupActivator, ClientSecretHasherActivator>());
        services.TryAddSingleton<IClientSecrets, ClientSecrets>();

        // A factory rather than type activation: the ISigningKeyRing parameter is optional, and DI
        // activation cannot supply a default for a service that is not registered.
        services.TryAddSingleton(sp => new ClientRegistrationValidator(
            sp.GetRequiredService<IOptions<AuthorizationServerOptions>>(),
            sp.GetRequiredService<ClientSecretHasherRegistry>(),
            sp.GetRequiredService<SanitizingLogger<ClientRegistrationValidator>>(),
            sp.GetService<ISigningKeyRing>()));
        services.TryAddSingleton<IClientRegistrationValidator>(sp => sp.GetRequiredService<ClientRegistrationValidator>());

        services.TryAddSingleton(sp => new ValidatedClientResolver(
            sp.GetRequiredService<IClientRepository>(),
            new FrameworkThenHostValidator(
                sp.GetRequiredService<ClientRegistrationValidator>(),
                sp.GetRequiredService<IClientRegistrationValidator>()),
            sp.GetRequiredService<SanitizingLogger<ValidatedClientResolver>>()));

        services.TryAddEnumerable(
            ServiceDescriptor.Scoped<IStartupVerifier, ClientRepositoryPresenceVerifier>());

        // Resolves IClientRepository at startup so its construction-time validation fails fast
        // rather than at first request.
        services.TryAddEnumerable(
            ServiceDescriptor.Scoped<IStartupActivator, ClientRepositoryActivator>());
    }

    /// <summary>
    /// Registers the default scope repository and the validated catalog every scope lookup goes
    /// through.
    /// </summary>
    private static void AddScopeServices(IServiceCollection services)
    {
        services.TryAddSingleton<IScopeRepository>(new InMemoryScopeRepository(StandardScopes.All));

        // The only path from IScopeRepository to a scope definition, so a custom repository's
        // output is validated wherever it is read and not only at startup.
        services.TryAddSingleton<ValidatedScopeCatalog>();

        // A startup check rather than IValidateOptions so the openid-scope check can be awaited
        // without risking a deadlock on synchronous, blocking async I/O. An activator because it
        // calls a caller-supplied IScopeRepository.
        services.TryAddEnumerable(
            ServiceDescriptor.Scoped<IStartupActivator, ScopePresenceActivator>());
    }
}
