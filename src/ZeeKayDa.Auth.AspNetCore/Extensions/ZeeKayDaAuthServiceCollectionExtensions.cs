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
    /// <see cref="AuthorizationServerOptions"/> validation runs with <c>ValidateOnStart()</c>, so
    /// a misconfigured server fails loudly at startup rather than at the first request. Call
    /// <c>app.UseRouting()</c> followed by <c>app.MapZeeKayDaAuth()</c> after building the
    /// application to register the OIDC protocol endpoints.
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

        // Canonicalizes and freezes CorsOrigins before validation runs.
        services.TryAddEnumerable(
            ServiceDescriptor.Singleton<
                IPostConfigureOptions<AuthorizationServerOptions>,
                AuthorizationServerOptionsPostConfigurer>());

        services.TryAddEnumerable(
            ServiceDescriptor.Singleton<
                IValidateOptions<AuthorizationServerOptions>,
                AuthorizationServerOptionsValidator>());

        services.AddZeeKayDaAuthCore();

        services.TryAddSingleton<IScopeRepository>(new InMemoryScopeRepository(StandardScopes.All));
        services.TryAddSingleton<IDiscoveryDocumentProvider, DiscoveryDocumentProvider>();

        // TryAddEnumerable keeps each endpoint registered exactly once across repeated calls.
        services.TryAddEnumerable(
            ServiceDescriptor.Singleton<IZeeKayDaEndpoint, DiscoveryEndpoint>());
        services.TryAddEnumerable(
            ServiceDescriptor.Singleton<IZeeKayDaEndpoint, PreAlphaAuthorizationEndpoint>());
        services.TryAddEnumerable(
            ServiceDescriptor.Singleton<IZeeKayDaEndpoint, PreAlphaTokenEndpoint>());
        services.TryAddEnumerable(
            ServiceDescriptor.Singleton<IZeeKayDaEndpoint, PreAlphaJwksEndpoint>());

        // Registered unconditionally so using it without any IClientSecretHasher gives a clear
        // error instead of a generic "service not registered" DI failure.
        services.TryAddSingleton<CompositeClientSecretHasher>();

        // Alias so repository authors can inject IClientSecretFactory without knowing about the
        // composite's internal structure.
        services.TryAddSingleton<IClientSecretFactory>(sp =>
            sp.GetRequiredService<CompositeClientSecretHasher>());

        services.TryAddSingleton<IClientRegistrationValidator, ClientRegistrationValidator>();

        services.TryAddEnumerable(
            ServiceDescriptor.Singleton<
                IValidateOptions<AuthorizationServerOptions>,
                ClientRepositoryPresenceValidator>());

        // The sanitizing-logger shadow gate and the runner that drives it are registered by
        // AddZeeKayDaAuthCore() above, so no ordering dependency exists here.
        services.TryAddEnumerable(
            ServiceDescriptor.Singleton<IStartupVerifier, InsecureIssuerWarningService>());
        services.TryAddEnumerable(
            ServiceDescriptor.Singleton<IStartupVerifier, ExceptionSanitizingDisabledWarningService>());
        services.TryAddEnumerable(
            ServiceDescriptor.Singleton<IStartupVerifier, AbsoluteFamilyLifetimeUnboundedWarningService>());

        // An IStartupVerifier rather than IValidateOptions so the openid-scope check can be
        // awaited without risking a deadlock on synchronous, blocking async I/O.
        services.TryAddEnumerable(
            ServiceDescriptor.Singleton<IStartupVerifier, ScopePresenceStartupValidator>());

        services.TryAddEnumerable(
            ServiceDescriptor.Singleton<IStartupVerifier, TokenStorePresenceValidator>());

        // Resolves IClientRepository at startup so its construction-time validation fails fast
        // rather than at first request.
        services.TryAddEnumerable(
            ServiceDescriptor.Singleton<IStartupVerifier, ClientRepositoryStartupActivator>());

        // The composite is registered as its concrete type, not IClientAuthenticator, so it is
        // excluded from IEnumerable<IClientAuthenticator> and cannot dispatch recursively.
        services.TryAddEnumerable(
            ServiceDescriptor.Singleton<IClientAuthenticator, ClientSecretAuthenticator>());
        services.TryAddSingleton<CompositeClientAuthenticator>();

        services.TryAddEnumerable(
            ServiceDescriptor.Singleton<
                IValidateOptions<AuthorizationServerOptions>,
                AuthenticatorCoverageValidator>());

        var builder = new ZeeKayDaAuthBuilder(services);
        builder.AddSecretsHasher<Pbkdf2ClientSecretHasher>(isDefault: true);
        return builder;
    }
}
