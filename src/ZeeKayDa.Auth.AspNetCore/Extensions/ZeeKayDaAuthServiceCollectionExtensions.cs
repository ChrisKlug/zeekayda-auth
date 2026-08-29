using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;
using ZeeKayDa.Auth;
using ZeeKayDa.Auth.AspNetCore;
using ZeeKayDa.Auth.AspNetCore.ClientAuthentication;
using ZeeKayDa.Auth.AspNetCore.Endpoints;
using ZeeKayDa.Auth.AspNetCore.Interaction;
using ZeeKayDa.Auth.Authorization;
using ZeeKayDa.Auth.Clients;
using ZeeKayDa.Auth.Configuration;
using ZeeKayDa.Auth.Discovery;
using ZeeKayDa.Auth.Extensions;
using ZeeKayDa.Auth.Logging;
using ZeeKayDa.Auth.Scopes;
using ZeeKayDa.Auth.Tokens;

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
            ServiceDescriptor.Singleton<IZeeKayDaEndpoint, AuthorizationEndpoint>());
        services.TryAddEnumerable(
            ServiceDescriptor.Singleton<IZeeKayDaEndpoint, PreAlphaTokenEndpoint>());
        services.TryAddEnumerable(
            ServiceDescriptor.Singleton<IZeeKayDaEndpoint, JwksEndpoint>());

        // Registered unconditionally so using it without any IClientSecretHasher gives a clear
        // error instead of a generic "service not registered" DI failure.
        services.TryAddSingleton<CompositeClientSecretHasher>();

        // Alias so repository authors can inject IClientSecretFactory without knowing about the
        // composite's internal structure.
        services.TryAddSingleton<IClientSecretFactory>(sp =>
            sp.GetRequiredService<CompositeClientSecretHasher>());

        // A factory rather than type activation: the ISigningKeyRing parameter is optional, and DI
        // activation cannot supply a default for a service that is not registered.
        services.TryAddSingleton<IClientRegistrationValidator>(sp => new ClientRegistrationValidator(
            sp.GetRequiredService<IOptions<AuthorizationServerOptions>>(),
            sp.GetRequiredService<CompositeClientSecretHasher>(),
            sp.GetRequiredService<ISanitizingLogger<ClientRegistrationValidator>>(),
            sp.GetService<ISigningKeyRing>()));

        services.TryAddEnumerable(
            ServiceDescriptor.Singleton<
                IValidateOptions<AuthorizationServerOptions>,
                ClientRepositoryPresenceValidator>());

        // The sanitizing-logger shadow gate and the runner that drives it are registered by
        // AddZeeKayDaAuthCore() above, so no ordering dependency exists here.
        services.TryAddEnumerable(
            ServiceDescriptor.Singleton<IStartupVerifier, InsecureIssuerWarningService>());
        services.TryAddEnumerable(
            ServiceDescriptor.Singleton<IStartupVerifier, MissingLoginPathWarningService>());
        services.TryAddEnumerable(
            ServiceDescriptor.Singleton<IStartupActivator, ReservedCookieNameValidator>());
        services.TryAddEnumerable(
            ServiceDescriptor.Singleton<IStartupVerifier, ExceptionSanitizingDisabledWarningService>());
        services.TryAddEnumerable(
            ServiceDescriptor.Singleton<IStartupVerifier, AbsoluteFamilyLifetimeUnboundedWarningService>());

        // A startup check rather than IValidateOptions so the openid-scope check can be awaited
        // without risking a deadlock on synchronous, blocking async I/O. An activator because it
        // calls a caller-supplied IScopeRepository.
        services.TryAddEnumerable(
            ServiceDescriptor.Singleton<IStartupActivator, ScopePresenceStartupValidator>());

        services.TryAddEnumerable(
            ServiceDescriptor.Singleton<IStartupVerifier, TokenStorePresenceValidator>());

        // The discovery document derives id_token_signing_alg_values_supported from the signing key
        // ring, so a host serving the protocol endpoints must have one. Failing startup here is what
        // keeps that from surfacing as a DI resolution error on the first discovery request.
        services.TryAddEnumerable(
            ServiceDescriptor.Singleton<IStartupVerifier, SigningKeyRingPresenceValidator>());

        // Resolves IClientRepository at startup so its construction-time validation fails fast
        // rather than at first request.
        services.TryAddEnumerable(
            ServiceDescriptor.Singleton<IStartupActivator, ClientRepositoryStartupActivator>());

        // The composite is registered as its concrete type, not IClientAuthenticator, so it is
        // excluded from IEnumerable<IClientAuthenticator> and cannot dispatch recursively.
        services.TryAddEnumerable(
            ServiceDescriptor.Singleton<IClientAuthenticator, ClientSecretAuthenticator>());
        services.TryAddSingleton<CompositeClientAuthenticator>();
        AddAuthorizationRequestServices(services);

        services.TryAddEnumerable(
            ServiceDescriptor.Singleton<
                IValidateOptions<AuthorizationServerOptions>,
                AuthenticatorCoverageValidator>());

        var builder = new ZeeKayDaAuthBuilder(services);
        builder.AddSecretsHasher<Pbkdf2ClientSecretHasher>(isDefault: true);
        return builder;
    }

    /// <summary>
    /// Registers the services behind the authorization endpoint: the validating client resolver
    /// every endpoint resolves clients through, request validation, and the error-interaction
    /// handoff to the host's error page.
    /// </summary>
    private static void AddAuthorizationRequestServices(IServiceCollection services)
    {
        services.AddHttpContextAccessor();

        // The framework depends on Data Protection throughout (store payload encryption, the
        // authorize error transport, and the interaction cookies to come). The default web host
        // registers it already; this covers minimal hosts, and is idempotent everywhere else.
        services.AddDataProtection();

        services.TryAddSingleton<ValidatedClientResolver>();
        services.TryAddSingleton<AuthorizeRequestValidator>();
        services.TryAddSingleton<TimeProvider>(TimeProvider.System);
        services.TryAddSingleton<AuthorizeErrorTransport>();
        services.TryAddSingleton<AuthorizationRequestContextTransport>();
        services.TryAddSingleton<LocalErrorResponse>();
        services.TryAddSingleton<SsoSession>();
        services.TryAddSingleton<AuthorizationFlow>();
        services.TryAddSingleton<IErrorInteraction, ErrorInteraction>();
        services.TryAddSingleton<ILoginInteraction, LoginInteraction>();

        AddInteractionCookies(services);
    }

    /// <summary>
    /// Registers the cookie schemes the framework owns. Plain <c>AddCookie</c> schemes, not a
    /// ZeeKayDa handler: every authentication-shaped question here is already answered by a
    /// handler that ships with ASP.NET Core, and a framework scheme would be a vehicle with no
    /// cargo.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The host names none of these, and none of them may become a default scheme: a host with no
    /// authentication of its own must keep failing closed rather than inheriting the SSO session
    /// as the answer to <c>[Authorize]</c> or as the target of an unqualified
    /// <c>HttpContext.SignInAsync</c>. Opting host pages into the SSO session is a separate,
    /// explicit feature (#593).
    /// </para>
    /// <para>
    /// <strong>All four are registered together, and that is load-bearing.</strong> ASP.NET Core
    /// promotes a lone registered scheme to the automatic default, so registering only the schemes
    /// in use today would hand a bare host exactly the silent grant described above.
    /// <c>zkd.external</c> and <c>zkd.pending</c> are consumed by the external-provider leg;
    /// registering them now also keeps their names from being taken.
    /// </para>
    /// </remarks>
    private static void AddInteractionCookies(IServiceCollection services)
    {
        var authentication = services.AddAuthentication();

        authentication.AddCookie(ZeeKayDaCookies.Session, options =>
        {
            ConfigureFrameworkCookie(options, ZeeKayDaCookies.Session);

            // Lax, not Strict: the session is read while answering a top-level GET the user
            // arrived at from the client's site, which is exactly what Strict withholds.
            options.Cookie.SameSite = SameSiteMode.Lax;

            // Stated rather than inherited. This is the ASP.NET Core default; making the SSO
            // session's lifetime configurable is #604.
            options.ExpireTimeSpan = TimeSpan.FromDays(14);
        });

        authentication.AddCookie(ZeeKayDaCookies.External, options =>
        {
            // The provider handler's sign-in target, read back by /connect/resume in the same
            // browser round trip and discarded — it exists for seconds.
            ConfigureFrameworkCookie(options, ZeeKayDaCookies.External);
            options.Cookie.SameSite = SameSiteMode.Lax;
            options.ExpireTimeSpan = TimeSpan.FromMinutes(5);
        });

        authentication.AddCookie(ZeeKayDaCookies.Pending, options =>
        {
            // A half-authenticated principal, read only from same-site requests to the host's own
            // pages, so it takes the strictest setting available.
            ConfigureFrameworkCookie(options, ZeeKayDaCookies.Pending);
            options.Cookie.SameSite = SameSiteMode.Strict;
            options.ExpireTimeSpan = TimeSpan.FromMinutes(15);
        });
    }

    private static void ConfigureFrameworkCookie(CookieAuthenticationOptions options, string name)
    {
        options.Cookie.Name = name;
        options.Cookie.HttpOnly = true;
        options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
        options.Cookie.IsEssential = true;

        // No sliding expiration anywhere: auth_time is a protocol value carried as a claim, never
        // inferred from a ticket's age, and a renewing window is not what any of these hold.
        options.SlidingExpiration = false;

        // Nothing redirects to a login page through these schemes — the authorization endpoint
        // owns that decision and needs the interaction context written first. A challenge or
        // forbid here is a bug, so it answers with a status code rather than a redirect that
        // would silently appear to work.
        options.Events.OnRedirectToLogin = context => WriteStatusCode(context, StatusCodes.Status401Unauthorized);
        options.Events.OnRedirectToAccessDenied = context => WriteStatusCode(context, StatusCodes.Status403Forbidden);
    }

    private static Task WriteStatusCode(RedirectContext<CookieAuthenticationOptions> context, int statusCode)
    {
        context.Response.StatusCode = statusCode;
        return Task.CompletedTask;
    }
}
