using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Routing;
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

        var builder = services.AddZeeKayDaAuthCore(configure);

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
            ServiceDescriptor.Singleton<IStartupActivator, AuthenticatorCoverageActivator>());

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
        services.TryAddSingleton<IErrorInteraction, ErrorInteraction>();
        services.TryAddSingleton<ILoginInteraction, LoginInteraction>();

        // Registered whether or not WithProviders is called: its job is to catch a host with
        // neither a login page nor a provider, so nothing can sign a user in.
        services.TryAddEnumerable(
            ServiceDescriptor.Singleton<IStartupVerifier, LoginDispatchVerifier>());

        services.TryAddSingleton<IConsentInteraction, ConsentInteraction>();
        services.TryAddSingleton<IProviderSignInInteraction, ProviderSignInInteraction>();
        services.TryAddSingleton<LogoutRequestStore>();
        services.TryAddSingleton<EndSessionResponses>();
        services.TryAddSingleton<ILogoutInteraction, LogoutInteraction>();

        // Lets a Razor Pages handler or controller action end with a plain await after a terminal
        // call. Inert on a host without MVC, which never reads MvcOptions.
        services.TryAddEnumerable(
            ServiceDescriptor.Singleton<IConfigureOptions<MvcOptions>, TerminalInteractionMvcOptionsSetup>());

        AddInteractionCookies(services);
        AddProviderServices(services);
    }

    /// <summary>
    /// Registers what external providers need before any is registered: an empty scheme map that
    /// <c>WithProviders</c> replaces, the validator that asserts the framework's pins on every
    /// registered provider's options, and the round trip — the challenge, one callback endpoint
    /// per provider, and the resume endpoint, each of which maps nothing while the map is empty.
    /// The pin itself is registered by <c>WithProviders</c>, at the tail of the collection, so it
    /// runs after the provider's own post-configuration.
    /// </summary>
    private static void AddProviderServices(IServiceCollection services)
    {
        services.TryAddSingleton(ProviderRegistry.Empty);
        services.TryAddSingleton<ProviderHandlerActivator>();
        services.TryAddEnumerable(
            ServiceDescriptor.Singleton<IZeeKayDaEndpoint, ProviderCallbackEndpoint>());
        services.TryAddEnumerable(
            ServiceDescriptor.Singleton<IZeeKayDaEndpoint, ResumeEndpoint>());

        // Open generic, constrained to AuthenticationSchemeOptions: the container skips it for
        // every other options type, and it skips itself for every name that is not a provider.
        services.TryAddEnumerable(
            ServiceDescriptor.Singleton(typeof(IValidateOptions<>), typeof(HandlerOptionsValidator<>)));

        // The channel that carries the validator's findings to the startup activator with their
        // provenance intact. Registered next to the validator because it is useless without it.
        services.TryAddSingleton<PinnedOptionDriftRecorder>();
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
            ServiceDescriptor.Singleton<IStartupActivator, ReservedCookieNameActivator>());

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
