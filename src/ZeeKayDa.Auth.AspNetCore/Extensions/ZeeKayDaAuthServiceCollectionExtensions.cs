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

namespace Microsoft.Extensions.DependencyInjection;

/// <summary>
/// Extension methods for <see cref="IServiceCollection"/> to register ZeeKayDa.Auth services.
/// </summary>
public static class ZeeKayDaAuthServiceCollectionExtensions
{
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
    /// A collection key replaces the default list: setting one <c>TokenEndpoint:AuthMethodsSupported</c>
    /// entry leaves that entry as the whole list. The values are read when the options are first
    /// resolved, so a configuration provider that reloads is not followed. In every other respect this
    /// is <see cref="AddZeeKayDaAuth(IServiceCollection, Action{AuthorizationServerOptions})"/>.
    /// </remarks>
    public static ZeeKayDaAuthBuilder AddZeeKayDaAuth(
        this IServiceCollection services,
        IConfiguration configuration,
        Action<AuthorizationServerOptions>? configure = null)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(configuration);

        return services.AddZeeKayDaAuth(options =>
        {
            AuthorizationServerOptionsBinder.Bind(configuration, options);
            configure?.Invoke(options);
        });
    }

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
    /// Calls <c>AddZeeKayDaAuthCore(configure)</c>, which registers and validates
    /// <see cref="AuthorizationServerOptions"/> so a misconfigured server fails loudly at startup
    /// rather than at the first request, and adds the endpoints, cookies, interaction and external
    /// providers on top. A repeated call adds its <paramref name="configure"/> delegate and registers
    /// nothing twice. Call <c>app.UseRouting()</c> followed by <c>app.MapZeeKayDaAuth()</c> after
    /// building the application to register the OIDC protocol endpoints.
    /// </remarks>
    public static ZeeKayDaAuthBuilder AddZeeKayDaAuth(
        this IServiceCollection services,
        Action<AuthorizationServerOptions> configure)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(configure);

        var builder = new ZeeKayDaAuthBuilder(services.AddZeeKayDaAuthCore(configure));

        // A repeated call adds only its configure delegate: the cookie schemes below cannot be
        // registered twice, so the HTTP surface is registered by the first call alone.
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

        // The composite is registered as its concrete type, not IClientAuthenticator, so it is
        // excluded from IEnumerable<IClientAuthenticator> and cannot dispatch recursively.
        services.TryAddEnumerable(
            ServiceDescriptor.Singleton<IClientAuthenticator, ClientSecretAuthenticator>());
        services.TryAddSingleton<CompositeClientAuthenticator>();

        services.TryAddEnumerable(
            ServiceDescriptor.Scoped<IStartupActivator, AuthenticatorCoverageActivator>());

        services.TryAddSingleton<GrantClaimsResolver>();
        services.TryAddSingleton<AuthorizationCodeGrant>();
        services.TryAddSingleton<TokenRequestHandler>();
        AddAuthorizationRequestServices(services);
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
        services.TryAddSingleton<AuthorizeErrorTransport>();
        services.TryAddSingleton<InteractionBindingCookie>();
        services.TryAddSingleton<AuthorizationRequestContextStore>();
        services.TryAddSingleton<AuthorizationResponses>();
        services.TryAddSingleton<SsoSession>();
        services.TryAddSingleton<PendingPrincipalStore>();
        services.TryAddSingleton<AuthorizationFlow>();
        services.TryAddSingleton<AuthorizationCodeIssuer>();
        services.TryAddSingleton<InteractionOutcomes>();
        services.TryAddSingleton<InteractionAnswers>();
        services.TryAddSingleton<NothingToContinue>();
        services.TryAddSingleton<PageInteractionServices>();
        // The interaction services are public sealed classes with internal constructors, which the
        // container cannot call, so each is built here; a host can consume them but never supply one.
        // Replaced, not tried: the framework is the only possible supplier, so its registration wins,
        // and calling this twice still leaves one.
        services.RemoveAll<ErrorInteraction>();
        services.AddSingleton(sp => new ErrorInteraction(
            sp.GetRequiredService<IHttpContextAccessor>(),
            sp.GetRequiredService<AuthorizeErrorTransport>()));
        services.RemoveAll<LoginInteraction>();
        services.AddSingleton(sp => new LoginInteraction(
            sp.GetRequiredService<IHttpContextAccessor>(),
            sp.GetRequiredService<IOptions<AuthorizationServerOptions>>(),
            sp.GetRequiredService<ProviderRegistry>(),
            sp.GetRequiredService<PageInteractionServices>()));

        // Registered whether or not WithProviders is called: its job is to catch a host with
        // neither a login page nor a provider, so nothing can sign a user in.
        services.TryAddEnumerable(
            ServiceDescriptor.Scoped<IStartupVerifier, LoginDispatchVerifier>());

        services.RemoveAll<ConsentInteraction>();
        services.AddSingleton(sp => new ConsentInteraction(
            sp.GetRequiredService<IHttpContextAccessor>(),
            sp.GetRequiredService<PageInteractionServices>()));
        services.RemoveAll<ProviderSignInInteraction>();
        services.AddSingleton(sp => new ProviderSignInInteraction(
            sp.GetRequiredService<IHttpContextAccessor>(),
            sp.GetRequiredService<ProviderRegistry>(),
            sp.GetRequiredService<PageInteractionServices>()));
        services.TryAddSingleton<LogoutRequestStore>();
        services.TryAddSingleton<EndSessionResponses>();
        services.RemoveAll<LogoutInteraction>();
        services.AddSingleton(sp => new LogoutInteraction(
            sp.GetRequiredService<IHttpContextAccessor>(),
            sp.GetRequiredService<LogoutRequestStore>(),
            sp.GetRequiredService<EndSessionResponses>(),
            sp.GetRequiredService<SsoSession>(),
            sp.GetRequiredService<NothingToContinue>()));

        // Lets a Razor Pages handler or controller action end with a plain await after a terminal
        // call. Inert on a host without MVC, which never reads MvcOptions.
        services.TryAddEnumerable(
            ServiceDescriptor.Singleton<IConfigureOptions<MvcOptions>, TerminalInteractionMvcOptionsSetup>());

        AddInteractionCookies(services);
        AddProviderServices(services);
    }

    /// <summary>
    /// Registers what external providers need before any is registered: an empty scheme map that
    /// <c>WithProviders</c> replaces, and the round trip — the challenge, one callback endpoint per
    /// provider, and the resume endpoint, each of which maps nothing while the map is empty. The
    /// pin, its validator and the provider startup checks are registered by <c>WithProviders</c>.
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
    /// <strong>Both are registered together, and that is load-bearing.</strong> ASP.NET Core
    /// promotes a lone registered scheme to the automatic default, so registering only the
    /// session scheme would hand a bare host exactly the silent grant described above.
    /// <c>zkd.external</c> serves the external-provider round trip, and is registered whether or
    /// not a provider is. The parked principal that <c>zkd.pending</c> once carried lives in the
    /// interaction store, so no scheme backs that name.
    /// </para>
    /// </remarks>
    private static void AddInteractionCookies(IServiceCollection services)
    {
        services.TryAddEnumerable(
            ServiceDescriptor.Scoped<IStartupActivator, ReservedCookieNameActivator>());

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

            // Only a provider's callback endpoint may sign in here, and the provider is what that
            // endpoint's route says: recorded from the request, refused without it.
            options.Events.OnSigningIn = ExternalTicket.RecordProvider;
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
