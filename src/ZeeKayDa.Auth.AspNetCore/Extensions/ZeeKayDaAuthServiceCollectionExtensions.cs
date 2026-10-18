using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;
using ZeeKayDa.Auth;
using ZeeKayDa.Auth.AspNetCore;
using ZeeKayDa.Auth.AspNetCore.ClientAuthentication;
using ZeeKayDa.Auth.AspNetCore.Endpoints;
using ZeeKayDa.Auth.AspNetCore.Interaction;
using ZeeKayDa.Auth.AspNetCore.Providers;
using ZeeKayDa.Auth.AspNetCore.Tokens;
using ZeeKayDa.Auth.StartupVerification;
using ZeeKayDa.Auth.Tokens;

namespace Microsoft.Extensions.DependencyInjection;

/// <summary>
/// Extension methods for <see cref="IServiceCollection"/> to register ZeeKayDa.Auth services.
/// </summary>
public static class ZeeKayDaAuthServiceCollectionExtensions
{
#pragma warning disable RS0026 // Optional trailing delegate on the issuer and configuration overloads; nothing is shipped to stay compatible with.
    /// <summary>
    /// Registers ZeeKayDa.Auth services for an authorization server with the given issuer.
    /// </summary>
    /// <param name="services">The service collection to add services to.</param>
    /// <param name="issuer">
    /// The issuer identifier, assigned to <see cref="AuthorizationServerOptions.Issuer"/> before
    /// <paramref name="configure"/> runs.
    /// </param>
    /// <param name="configure">An optional delegate used to configure the remaining options.</param>
    /// <returns>
    /// A <see cref="ZeeKayDaAuthBuilder"/> that can be used to register optional features.
    /// </returns>
    /// <exception cref="ArgumentNullException">
    /// Thrown when <paramref name="services"/> or <paramref name="issuer"/> is <see langword="null"/>.
    /// </exception>
    /// <remarks>
    /// In every other respect this is <see cref="AddZeeKayDaAuth(IServiceCollection, Action{AuthorizationServerOptions})"/>.
    /// </remarks>
    public static ZeeKayDaAuthBuilder AddZeeKayDaAuth(
        this IServiceCollection services,
        string issuer,
        Action<AuthorizationServerOptions>? configure = null)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(issuer);

        return services.AddZeeKayDaAuth(Then(options => options.Issuer = issuer, configure));
    }

    /// <summary>
    /// Registers ZeeKayDa.Auth services, configuring <see cref="AuthorizationServerOptions"/> from
    /// a configuration section.
    /// </summary>
    /// <param name="services">The service collection to add services to.</param>
    /// <param name="configuration">
    /// The configuration section whose keys are the names of the <see cref="AuthorizationServerOptions"/>
    /// properties, such as <c>Issuer</c> and <c>TokenEndpoint:AccessTokenLifetime</c>. Enums bind by name.
    /// </param>
    /// <param name="configure">
    /// An optional delegate that runs after the section is bound, for what configuration cannot hold.
    /// </param>
    /// <returns>
    /// A <see cref="ZeeKayDaAuthBuilder"/> that can be used to register optional features.
    /// </returns>
    /// <exception cref="ArgumentNullException">
    /// Thrown when <paramref name="services"/> or <paramref name="configuration"/> is
    /// <see langword="null"/>.
    /// </exception>
    /// <remarks>
    /// A collection key replaces the default list, and an empty JSON array (<c>[]</c>) empties it.
    /// The framework reads these options once, so a reloading configuration provider does not change
    /// the running server. In every other respect this is
    /// <see cref="AddZeeKayDaAuth(IServiceCollection, Action{AuthorizationServerOptions})"/>.
    /// </remarks>
    public static ZeeKayDaAuthBuilder AddZeeKayDaAuth(
        this IServiceCollection services,
        IConfiguration configuration,
        Action<AuthorizationServerOptions>? configure = null)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(configuration);

        return services.AddZeeKayDaAuth(Then(options => AuthorizationServerOptionsBinder.Bind(configuration, options), configure));
    }
#pragma warning restore RS0026

    /// <summary>One options delegate: <paramref name="first"/>, then the host's <paramref name="configure"/>.</summary>
    private static Action<AuthorizationServerOptions> Then(
        Action<AuthorizationServerOptions> first,
        Action<AuthorizationServerOptions>? configure) =>
        options =>
        {
            first(options);
            configure?.Invoke(options);
        };

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
    /// Adds the endpoints, cookies and interaction services to <c>AddZeeKayDaAuthCore</c>, which
    /// validates the options at startup. A repeated call adds only its <paramref name="configure"/>.
    /// Map the endpoints with <c>app.UseRouting()</c>, then <c>app.MapZeeKayDaAuth()</c>.
    /// </remarks>
    public static ZeeKayDaAuthBuilder AddZeeKayDaAuth(
        this IServiceCollection services,
        Action<AuthorizationServerOptions> configure)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(configure);

        var builder = new ZeeKayDaAuthBuilder(services.AddZeeKayDaAuthCore(configure));

        // The cookie schemes below cannot be registered twice.
        if (services.Any(descriptor => descriptor.ServiceType == typeof(IZeeKayDaEndpoint)))
            return builder;

        services.TryAddSingleton<CorsAllowlist>();
        services.TryAddEnumerable(
            ServiceDescriptor.Singleton<IZeeKayDaEndpoint, DiscoveryEndpoint>());
        services.TryAddEnumerable(
            ServiceDescriptor.Singleton<IZeeKayDaEndpoint, AuthorizationEndpoint>());
        services.TryAddEnumerable(
            ServiceDescriptor.Singleton<IZeeKayDaEndpoint, TokenEndpoint>());
        services.TryAddEnumerable(
            ServiceDescriptor.Singleton<IZeeKayDaEndpoint, JwksEndpoint>());
        services.TryAddEnumerable(
            ServiceDescriptor.Singleton<IZeeKayDaEndpoint, UserInfoEndpoint>());
        services.TryAddEnumerable(
            ServiceDescriptor.Singleton<IZeeKayDaEndpoint, EndSessionEndpoint>());

        // Every framework route matches its path exactly; see ExactPathMatcherPolicy.
        services.TryAddEnumerable(
            ServiceDescriptor.Singleton<MatcherPolicy, ExactPathMatcherPolicy>());

        // The composite as its concrete type, so it cannot dispatch to itself.
        services.TryAddEnumerable(
            ServiceDescriptor.Singleton<IClientAuthenticator, ClientSecretAuthenticator>());
        services.TryAddSingleton(sp => new RegisteredAuthenticators(sp.GetServices<IClientAuthenticator>()));
        services.TryAddSingleton<CompositeClientAuthenticator>();

        // Replaces the core's authenticator-less default: the HTTP layer is what performs methods.
        services.RemoveAll<AdvertisedAuthMethods>();
        services.AddSingleton(RegisteredAuthenticators.Advertise);

        services.TryAddEnumerable(
            ServiceDescriptor.Scoped<IStartupActivator, ClientAuthenticatorActivator>());

        services.TryAddSingleton<GrantClaimsResolver>();
        services.TryAddSingleton<AuthorizationCodeGrant>();
        services.TryAddSingleton<TokenRequestHandler>();
        AddAuthorizationRequestServices(services);
        return builder;
    }

    /// <summary>Registers the services behind the authorization endpoint and the host's interaction pages.</summary>
    private static void AddAuthorizationRequestServices(IServiceCollection services)
    {
        services.AddHttpContextAccessor();
        services.TryAddSingleton<AuthorizeErrorTransport>();
        services.TryAddSingleton<InteractionBindingCookie>();
        services.TryAddSingleton<AuthorizationRequestContextStore>();
        services.TryAddSingleton<AuthorizationResponses>();
        services.TryAddSingleton<SsoSession>();
        services.TryAddSingleton<PendingPrincipalStore>();
        services.TryAddSingleton<AuthorizationFlow>();
        services.TryAddSingleton<AuthorizationCodeIssuer>();
        services.TryAddSingleton<ProviderChallengeHook>();
        services.TryAddSingleton<InteractionOutcomes>();
        services.TryAddSingleton<InteractionAnswers>();
        services.TryAddSingleton<NothingToContinue>();
        services.TryAddSingleton<PageInteractionServices>();
        AddFrameworkBuilt(services, sp => new ErrorInteraction(
            sp.GetRequiredService<IHttpContextAccessor>(),
            sp.GetRequiredService<AuthorizeErrorTransport>()));
        AddFrameworkBuilt(services, sp => new LoginInteraction(
            sp.GetRequiredService<IHttpContextAccessor>(),
            sp.GetRequiredService<IOptions<AuthorizationServerOptions>>(),
            sp.GetRequiredService<ProviderRegistry>(),
            sp.GetRequiredService<PageInteractionServices>()));

        // Whether or not WithProviders is called: it catches a host with no way to sign anyone in.
        services.TryAddEnumerable(
            ServiceDescriptor.Scoped<IStartupVerifier, LoginDispatchVerifier>());

        AddFrameworkBuilt(services, sp => new ConsentInteraction(
            sp.GetRequiredService<IHttpContextAccessor>(),
            sp.GetRequiredService<PageInteractionServices>()));
        AddFrameworkBuilt(services, sp => new AccountSelectionInteraction(
            sp.GetRequiredService<IHttpContextAccessor>(),
            sp.GetRequiredService<PageInteractionServices>()));
        AddFrameworkBuilt(services, sp => new ProviderSignInInteraction(
            sp.GetRequiredService<IHttpContextAccessor>(),
            sp.GetRequiredService<ProviderRegistry>(),
            sp.GetRequiredService<PageInteractionServices>()));
        services.TryAddSingleton<LogoutRequestStore>();
        services.TryAddSingleton<EndSessionResponses>();
        AddFrameworkBuilt(services, sp => new LogoutInteraction(
            sp.GetRequiredService<IHttpContextAccessor>(),
            sp.GetRequiredService<LogoutRequestStore>(),
            sp.GetRequiredService<EndSessionResponses>(),
            sp.GetRequiredService<SsoSession>(),
            sp.GetRequiredService<NothingToContinue>()));

        services.TryAddEnumerable(
            ServiceDescriptor.Singleton<IConfigureOptions<MvcOptions>, TerminalInteractionMvcOptionsSetup>());

        AddInteractionCookies(services);
        AddProviderServices(services);
    }

    /// <summary>
    /// Registers a public interaction service whose constructor is internal, replacing any other
    /// registration: the framework is its only possible supplier.
    /// </summary>
    private static void AddFrameworkBuilt<TService>(IServiceCollection services, Func<IServiceProvider, TService> factory)
        where TService : class
    {
        services.RemoveAll<TService>();
        services.AddSingleton(factory);
    }

    /// <summary>
    /// Registers what external providers need before any is: an empty scheme map for
    /// <c>WithProviders</c> to replace, and endpoints that map nothing while it is empty.
    /// </summary>
    private static void AddProviderServices(IServiceCollection services)
    {
        services.TryAddSingleton(ProviderRegistry.Empty);
        services.TryAddSingleton<ProviderHandlerActivator>();
        services.TryAddEnumerable(
            ServiceDescriptor.Singleton<IZeeKayDaEndpoint, ProviderCallbackEndpoint>());
        services.TryAddEnumerable(
            ServiceDescriptor.Singleton<IZeeKayDaEndpoint, ResumeEndpoint>());
    }

    /// <summary>Registers the framework's cookie schemes, plain <c>AddCookie</c> ones.</summary>
    /// <remarks>
    /// None may become a default scheme, or a host with no authentication of its own would answer
    /// <c>[Authorize]</c> with the SSO session. Both are always registered for that reason: ASP.NET
    /// Core promotes a lone scheme to the default.
    /// </remarks>
    private static void AddInteractionCookies(IServiceCollection services)
    {
        services.TryAddEnumerable(
            ServiceDescriptor.Scoped<IStartupActivator, ReservedCookieNameActivator>());

        var authentication = services.AddAuthentication();

        authentication.AddCookie(ZeeKayDaCookies.Session, options =>
        {
            ConfigureFrameworkCookie(options, ZeeKayDaCookies.Session);

            // Not Strict: it is read on a top-level GET arriving from the client's site.
            options.Cookie.SameSite = SameSiteMode.Lax;

            // The ASP.NET Core default, stated rather than inherited.
            options.ExpireTimeSpan = TimeSpan.FromDays(14);
        });

        authentication.AddCookie(ZeeKayDaCookies.External, options =>
        {
            // Read back and discarded by /connect/resume in the same round trip.
            ConfigureFrameworkCookie(options, ZeeKayDaCookies.External);
            options.Cookie.SameSite = SameSiteMode.Lax;
            options.ExpireTimeSpan = TimeSpan.FromMinutes(5);

            options.Events.OnSigningIn = ExternalTicket.RecordProvider;
        });
    }

    private static void ConfigureFrameworkCookie(CookieAuthenticationOptions options, string name)
    {
        options.Cookie.Name = name;
        options.Cookie.HttpOnly = true;
        options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
        options.Cookie.IsEssential = true;

        // auth_time is carried as a claim, never inferred from a ticket's age.
        options.SlidingExpiration = false;

        // A challenge through these schemes is a bug; a redirect would hide it.
        options.Events.OnRedirectToLogin = context => WriteStatusCode(context, StatusCodes.Status401Unauthorized);
        options.Events.OnRedirectToAccessDenied = context => WriteStatusCode(context, StatusCodes.Status403Forbidden);
    }

    private static Task WriteStatusCode(RedirectContext<CookieAuthenticationOptions> context, int statusCode)
    {
        context.Response.StatusCode = statusCode;
        return Task.CompletedTask;
    }
}
