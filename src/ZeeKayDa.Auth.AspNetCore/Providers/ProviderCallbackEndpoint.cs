using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using ZeeKayDa.Auth.AspNetCore.Endpoints;
using ZeeKayDa.Auth.AspNetCore.Interaction;
using ZeeKayDa.Auth.Authorization;
using ZeeKayDa.Auth.Logging;

namespace ZeeKayDa.Auth.AspNetCore.Providers;

/// <summary>
/// One routed endpoint per registered provider at <c>/connect/callback/{provider}</c> under the
/// issuer path — the same route the framework pinned into the handler's <c>CallbackPath</c>, so
/// the handler's own path check passes by construction. Marks the request with the provider the
/// route names, then hands it to that provider's own handler, which completes the protocol, signs
/// into <c>zkd.external</c> and redirects to <c>/connect/resume</c>.
/// </summary>
/// <remarks>
/// <para>
/// The endpoint owns the outcomes the handler does not. A handler declining its own callback is
/// logged and answered with an empty 404, never fallen through to the next middleware. A failure
/// is classified: only a refusal by the user at the provider, recorded on the request by the
/// framework's own access-denied event, reaches the client as <c>access_denied</c> — and only
/// when the refused challenge names the interaction this browser is carrying. Everything else
/// renders the local error page and leaves the interaction untouched, so the user can try again
/// and a stray or replayed callback can neither complete nor cancel a live request.
/// </para>
/// <para>
/// Failures are logged by exception type, never by message: a remote failure's message embeds
/// what the provider said.
/// </para>
/// </remarks>
internal sealed class ProviderCallbackEndpoint : IZeeKayDaEndpoint
{
    private const string DeclinedAtProvider =
        "The user declined to sign in at the external identity provider.";

    private const string DidNotComplete =
        "Sign-in at the external identity provider did not complete. Return to the application and try again.";

    private readonly IOptions<AuthorizationServerOptions> _options;
    private readonly ProviderRegistry _providers;
    private readonly ProviderHandlerActivator _activator;
    private readonly AuthorizationFlow _flow;
    private readonly LocalErrorResponse _localError;
    private readonly ClientErrorRedirect _clientError;
    private readonly ISanitizingLogger<ProviderCallbackEndpoint> _logger;

    public ProviderCallbackEndpoint(
        IOptions<AuthorizationServerOptions> options,
        ProviderRegistry providers,
        ProviderHandlerActivator activator,
        AuthorizationFlow flow,
        LocalErrorResponse localError,
        ClientErrorRedirect clientError,
        ISanitizingLogger<ProviderCallbackEndpoint> logger)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(providers);
        ArgumentNullException.ThrowIfNull(activator);
        ArgumentNullException.ThrowIfNull(flow);
        ArgumentNullException.ThrowIfNull(localError);
        ArgumentNullException.ThrowIfNull(clientError);
        ArgumentNullException.ThrowIfNull(logger);

        _options = options;
        _providers = providers;
        _activator = activator;
        _flow = flow;
        _localError = localError;
        _clientError = clientError;
        _logger = logger;
    }

    /// <inheritdoc/>
    public void Map(IEndpointRouteBuilder endpoints)
    {
        var issuerUri = EndpointRouteHelper.GetIssuerUri(_options);

        foreach (var registration in _providers.Registrations)
        {
            var route = ProviderCallbackRoute.For(issuerUri, registration.Name);

            // Typed as Delegate so the result-writing overload is chosen: a lambda taking only
            // the context also converts to RequestDelegate, whose overload discards the returned
            // result. AllowAnonymous so a host-wide authorization fallback policy cannot turn the
            // return from the provider into a challenge of the host's own scheme.
            Delegate handler = (HttpContext context) => HandleAsync(context, registration);
            endpoints.MapMethods(route.Value!, [HttpMethods.Get, HttpMethods.Post], handler)
                .RequireIssuerHost(issuerUri)
                .AllowAnonymous();
        }
    }

    private async Task<IResult> HandleAsync(HttpContext context, ProviderRegistration registration)
    {
        context.Response.Headers.CacheControl = "no-store";

        // Set after routing and before the handler runs: the provider is what the route says,
        // never what the request or the handler says.
        var feature = new ProviderCallbackFeature(registration);
        context.Features.Set(feature);

        // Activation is inside the guarded path too: a handler's constructor or InitializeAsync
        // is caller-supplied code, and a failure there is the provider not completing, not a
        // server fault to surface unsanitized.
        bool handled;
        try
        {
            var handler = await _activator.ActivateAsync(context, registration).ConfigureAwait(false);
            if (handler is not IAuthenticationRequestHandler requestHandler)
            {
                _logger.LogError(
                    "The handler for provider {Provider} does not handle requests, so its callback cannot be completed.",
                    registration.Name);
                return Results.NotFound();
            }

            handled = await requestHandler.HandleRequestAsync().ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            return Fail(context, feature, ex);
        }

        if (handled)
            return Results.Empty;

        _logger.LogError("The handler for provider {Provider} declined its own callback.", registration.Name);
        return Results.NotFound();
    }

    private IResult Fail(HttpContext context, ProviderCallbackFeature feature, Exception exception)
    {
        if (!feature.Refused)
        {
            _logger.LogError(
                "The handler for provider {Provider} failed its callback with {ExceptionType}.",
                feature.Provider.Name,
                exception.GetType().FullName);
            return _localError.Render(context, AuthorizeRequestErrors.ServerError, DidNotComplete);
        }

        _logger.LogInformation("The user declined to sign in at provider {Provider}.", feature.Provider.Name);

        // The refusal reaches the client only for the interaction this browser is carrying and
        // the refused challenge was issued for. Without the interaction cookie — a form_post
        // callback is a cross-site POST the Lax cookie does not accompany — or with a mismatch,
        // the refusal renders locally and the interaction, if any, survives.
        var requestContext = _flow.Read(context);
        if (requestContext is null
            || feature.RefusedInteractionId is null
            || !InteractionHandoff.IdentifiersMatch(requestContext.Id, feature.RefusedInteractionId))
        {
            return _localError.Render(context, AuthorizeRequestErrors.AccessDenied, DeclinedAtProvider);
        }

        _flow.Clear(context);
        return _clientError.To(
            requestContext.RedirectUri,
            AuthorizeRequestErrors.AccessDenied,
            DeclinedAtProvider,
            requestContext.State);
    }
}
