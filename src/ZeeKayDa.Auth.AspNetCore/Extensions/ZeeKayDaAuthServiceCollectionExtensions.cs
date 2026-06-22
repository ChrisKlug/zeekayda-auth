using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;
using ZeeKayDa.Auth;
using ZeeKayDa.Auth.AspNetCore;
using ZeeKayDa.Auth.AspNetCore.ClientAuthentication;
using ZeeKayDa.Auth.AspNetCore.Endpoints;
using ZeeKayDa.Auth.Clients;
using ZeeKayDa.Auth.Configuration;
using ZeeKayDa.Auth.Discovery;
using ZeeKayDa.Auth.Extensions;
using ZeeKayDa.Auth.Scopes;

namespace Microsoft.Extensions.DependencyInjection;

/// <summary>
/// Extension methods for <see cref="IServiceCollection"/> to register ZeeKayDa.Auth services.
/// </summary>
public static class ZeeKayDaAuthServiceCollectionExtensions
{
    /// <summary>
    /// Registers ZeeKayDa.Auth services in the dependency injection container.
    /// </summary>
    /// <param name="services">The service collection to add services to.</param>
    /// <param name="configure">
    /// A delegate used to configure <see cref="AuthorizationServerOptions"/>. At minimum,
    /// <see cref="AuthorizationServerOptions.Issuer"/> must be set.
    /// </param>
    /// <returns>
    /// A <see cref="ZeeKayDaAuthBuilder"/> that can be used to register optional features.
    /// </returns>
    /// <exception cref="ArgumentNullException">
    /// Thrown when <paramref name="services"/> or <paramref name="configure"/> is
    /// <see langword="null"/>.
    /// </exception>
    /// <remarks>
    /// <para>
    /// Validation of <see cref="AuthorizationServerOptions"/> is activated with
    /// <c>ValidateOnStart()</c>, so a misconfigured server (for example, a missing or HTTP
    /// issuer) fails loudly at startup rather than silently at the first request.
    /// </para>
    /// <para>
    /// Call <c>app.UseRouting()</c> followed by <c>app.MapZeeKayDaAuth()</c> after building the
    /// application to register the OIDC protocol endpoints.
    /// </para>
    /// </remarks>
    public static ZeeKayDaAuthBuilder AddZeeKayDaAuth(
        this IServiceCollection services,
        Action<AuthorizationServerOptions> configure)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(configure);

        services
            .AddOptions<AuthorizationServerOptions>()
            .Configure(configure)
            .ValidateOnStart();

        // Post-configurer runs before validation: canonicalizes and freezes CorsOrigins so the
        // validator is a pure read-only check.
        services.TryAddEnumerable(
            ServiceDescriptor.Singleton<
                IPostConfigureOptions<AuthorizationServerOptions>,
                AuthorizationServerOptionsPostConfigurer>());

        // Validator lives in ZeeKayDa.Auth (core) so it can be tested without a web host.
        services.TryAddEnumerable(
            ServiceDescriptor.Singleton<
                IValidateOptions<AuthorizationServerOptions>,
                AuthorizationServerOptionsValidator>());

        // Register core infrastructure (SecretSanitizingLogger<T> open-generic singleton).
        // Idempotent: TryAdd inside AddZeeKayDaAuthCore is a no-op on repeated calls.
        services.AddZeeKayDaAuthCore();

        services.TryAddSingleton<IScopeRepository>(new InMemoryScopeRepository(StandardScopes.All));
        services.TryAddSingleton<IDiscoveryDocumentProvider, DiscoveryDocumentProvider>();

        // Each endpoint is registered exactly once even if AddZeeKayDaAuth() is called multiple
        // times, because TryAddEnumerable checks the implementation type for uniqueness.
        services.TryAddEnumerable(
            ServiceDescriptor.Singleton<IZeeKayDaEndpoint, DiscoveryEndpoint>());
        services.TryAddEnumerable(
            ServiceDescriptor.Singleton<IZeeKayDaEndpoint, PreAlphaAuthorizationEndpoint>());
        services.TryAddEnumerable(
            ServiceDescriptor.Singleton<IZeeKayDaEndpoint, PreAlphaTokenEndpoint>());
        services.TryAddEnumerable(
            ServiceDescriptor.Singleton<IZeeKayDaEndpoint, PreAlphaJwksEndpoint>());

        // Always register the composite hasher so that attempting to use it without registering
        // any IClientSecretHasher implementations produces a clear error rather than a generic
        // "service not registered" DI failure.
        services.TryAddSingleton<CompositeClientSecretHasher>();

        // Register IClientSecretFactory as an alias for the already-constructed
        // CompositeClientSecretHasher singleton so custom repository authors can inject it
        // without knowing about the composite's internal structure.
        services.TryAddSingleton<IClientSecretFactory>(sp =>
            sp.GetRequiredService<CompositeClientSecretHasher>());

        // Register the client registration validator so custom repositories can resolve it.
        services.TryAddSingleton<IClientRegistrationValidator, ClientRegistrationValidator>();

        // Startup validation: fails if no IClientRepository has been registered. Runs as part of
        // the existing AuthorizationServerOptions ValidateOnStart() hook.
        services.TryAddEnumerable(
            ServiceDescriptor.Singleton<
                IValidateOptions<AuthorizationServerOptions>,
                ClientRepositoryPresenceValidator>());

        // Emits a startup warning when AllowInsecureIssuer is enabled.
        services.AddHostedService<InsecureIssuerWarningService>();

        // Emits a startup warning when exception message sanitization is disabled via
        // AuthorizationServerOptions.Logging.DisableExceptionSanitizing.
        services.AddHostedService<ExceptionSanitizingDisabledWarningService>();

        // Validates that IScopeRepository exposes the 'openid' scope. Done in a hosted service
        // so the check is awaitable — IValidateOptions<T>.Validate is synchronous and blocking
        // on async I/O risks deadlocks in certain hosting configurations.
        services.AddHostedService<ScopePresenceStartupValidator>();

        // Startup validation: fails if no IAuthorizationCodeStore or IRefreshTokenStore has
        // been registered. Uses IServiceProviderIsService to inspect the container without
        // resolving the services, so it fires before any store is constructed.
        services.AddHostedService<TokenStorePresenceValidator>();

        // Resolves IClientRepository at startup so construction-time validation (duplicate
        // detection, per-client validation, secret hashing) fails fast rather than at first request.
        services.AddHostedService<ClientRepositoryStartupActivator>();

        // Register the built-in client secret authenticator and composite dispatcher. Both are
        // registered as singletons. The composite is registered as its concrete type (not as
        // IClientAuthenticator) so it is excluded from the IEnumerable<IClientAuthenticator>
        // injection and cannot dispatch recursively.
        services.TryAddEnumerable(
            ServiceDescriptor.Singleton<IClientAuthenticator, ClientSecretAuthenticator>());
        services.TryAddSingleton<CompositeClientAuthenticator>();

        // Startup validation: every method in AuthMethodsSupported must be covered by exactly
        // one registered IClientAuthenticator; none may overlap or declare "none".
        services.TryAddEnumerable(
            ServiceDescriptor.Singleton<
                IValidateOptions<AuthorizationServerOptions>,
                AuthenticatorCoverageValidator>());

        var builder = new ZeeKayDaAuthBuilder(services);
        builder.AddSecretsHasher<Pbkdf2ClientSecretHasher>(isDefault: true);
        return builder;
    }
}
