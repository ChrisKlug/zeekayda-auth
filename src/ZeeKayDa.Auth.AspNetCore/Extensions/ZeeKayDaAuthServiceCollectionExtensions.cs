using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;
using ZeeKayDa.Auth;
using ZeeKayDa.Auth.AspNetCore.Endpoints;
using ZeeKayDa.Auth.Configuration;
using ZeeKayDa.Auth.Discovery;
using ZeeKayDa.Auth.Scopes;

namespace ZeeKayDa.Auth.AspNetCore.Extensions;

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

        // Validator lives in ZeeKayDa.Auth (core) so it can be tested without a web host.
        services.TryAddEnumerable(
            ServiceDescriptor.Singleton<
                IValidateOptions<AuthorizationServerOptions>,
                AuthorizationServerOptionsValidator>());

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

        // Emits a startup warning when AllowInsecureIssuer is enabled.
        services.AddHostedService<InsecureIssuerWarningService>();

        return new ZeeKayDaAuthBuilder(services);
    }
}
