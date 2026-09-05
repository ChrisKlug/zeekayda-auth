using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using ZeeKayDa.Auth.AspNetCore.Endpoints;
using ZeeKayDa.Auth.AspNetCore.Providers;
using ZeeKayDa.Auth.Authorization;
using ZeeKayDa.Auth.Logging;

namespace ZeeKayDa.Auth.AspNetCore.Interaction;

/// <summary>
/// The ways an interaction step ends, shared by every endpoint and page service that ends one:
/// a local error page, an error at the client's registered redirect URI, a denial, a completed
/// sign-in, a challenge to an external provider, and a parked principal sent on to a host page.
/// </summary>
/// <remarks>
/// <para>
/// The terminal outcomes write <em>and commit</em> the response. Executing a redirect result sets
/// the status and <c>Location</c> without flushing, leaving <see cref="HttpResponse.HasStarted"/>
/// false, so a host page that returns a result of its own after calling a terminal method would
/// silently replace both — which for a deny is the open redirect the interaction identifier
/// exists to prevent, written in host code where nothing validates it. Starting the response
/// commits the headers and turns that mistake into an exception the first time the page runs.
/// </para>
/// <para>
/// Every outcome that leaves the interaction takes the destination from validated state — the
/// decrypted context, a registered provider — never from request input.
/// </para>
/// </remarks>
internal sealed class InteractionOutcomes
{
    private const string TooLarge = "The authorization request is too large to process.";

    private readonly AuthorizationFlow _flow;
    private readonly LocalErrorResponse _localError;
    private readonly ClientErrorRedirect _clientError;
    private readonly ProviderHandlerActivator _activator;
    private readonly IOptions<AuthorizationServerOptions> _options;
    private readonly ISanitizingLogger<InteractionOutcomes> _logger;

    public InteractionOutcomes(
        AuthorizationFlow flow,
        LocalErrorResponse localError,
        ClientErrorRedirect clientError,
        ProviderHandlerActivator activator,
        IOptions<AuthorizationServerOptions> options,
        ISanitizingLogger<InteractionOutcomes> logger)
    {
        ArgumentNullException.ThrowIfNull(flow);
        ArgumentNullException.ThrowIfNull(localError);
        ArgumentNullException.ThrowIfNull(clientError);
        ArgumentNullException.ThrowIfNull(activator);
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(logger);

        _flow = flow;
        _localError = localError;
        _clientError = clientError;
        _activator = activator;
        _options = options;
        _logger = logger;
    }

    /// <summary>An error that must not reach the client: the host's error page, or the framework's minimal one.</summary>
    public IResult LocalError(HttpContext context, string error, string description) =>
        _localError.Render(context, error, description);

    /// <summary>
    /// An error at a redirect URI authenticated in phase 1, for a request whose interaction
    /// context was never written or is cleared by the caller.
    /// </summary>
    public IResult ClientError(string redirectUri, string error, string description, string? state) =>
        _clientError.To(redirectUri, error, description, state);

    /// <summary>
    /// An error at the client's registered redirect URI, read out of the encrypted context. The
    /// interaction is discarded first: a request that ends in an error is not resumed later.
    /// </summary>
    public IResult ClientError(HttpContext context, AuthorizationRequestContext requestContext, string error, string description)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(requestContext);

        _flow.Clear(context);
        return _clientError.To(requestContext.RedirectUri, error, description, requestContext.State);
    }

    /// <summary>
    /// Terminal. Ends the request with <c>access_denied</c> at the client's registered redirect
    /// URI, discarding the interaction and any principal parked for it. No session is promoted
    /// and none is read.
    /// </summary>
    public async Task DenyAsync(HttpContext context, AuthorizationRequestContext requestContext, string description)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(requestContext);

        context.Response.Headers.CacheControl = "no-store";

        // Discarded before the response is written, so a denied request cannot be resumed by a
        // later sign-in picking the context back up — nor by a parked principal bound to it.
        _flow.Clear(context);
        await _flow.ConsumePendingAsync(context, requestContext.Id).ConfigureAwait(false);

        await WriteAsync(
                context,
                _clientError.To(requestContext.RedirectUri, AuthorizeRequestErrors.AccessDenied, description, requestContext.State))
            .ConfigureAwait(false);
    }

    /// <summary>
    /// Terminal. Promotes <paramref name="principal"/> to the SSO session, records the
    /// authentication on the interaction context, and continues the flow. A principal parked for
    /// this interaction is consumed, and the provider that parked it is recorded when
    /// <paramref name="providerScheme"/> names none.
    /// </summary>
    /// <remarks>
    /// The session and the authenticated context are written before the flow continues, so the
    /// consent page reads a request that already knows who answered it.
    /// </remarks>
    public async Task CompleteSignInAsync(
        HttpContext context,
        AuthorizationRequestContext requestContext,
        ClaimsPrincipal principal,
        IReadOnlyList<string> authenticationMethods,
        string? providerScheme)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(requestContext);
        ArgumentNullException.ThrowIfNull(principal);
        ArgumentNullException.ThrowIfNull(authenticationMethods);

        // Responses on this path carry protocol material once code issuance lands, and a cached
        // sign-in response is a stolen one.
        context.Response.Headers.CacheControl = "no-store";

        var pending = await _flow.ConsumePendingAsync(context, requestContext.Id).ConfigureAwait(false);
        var state = await _flow.PromoteAsync(context, principal, authenticationMethods).ConfigureAwait(false);

        var authenticated = requestContext with
        {
            SsoSessionId = state.SessionId,
            Subject = state.Subject,
            AuthTime = state.AuthTime,
            Amr = state.Amr,
            ProviderScheme = providerScheme ?? pending?.Provider,
        };

        // Only unpersistable for a context already near the size ceiling before a few small
        // fields were added to it. The session is established either way — what cannot continue
        // is this authorization request, so it fails where the oversize did.
        var result = _flow.TryPersist(context, authenticated)
            ? await ContinueAsync(context, authenticated).ConfigureAwait(false)
            : FailTooLarge(context);

        await WriteAsync(context, result).ConfigureAwait(false);
    }

    /// <summary>
    /// The step after authentication, for a request just signed in or one an existing session
    /// answered for: to the host's consent page when the client requires consent, or straight on
    /// to code issuance when it does not. Not terminal — the caller writes the result.
    /// </summary>
    /// <remarks>
    /// No remembered grant exists yet, so a client that requires consent is asked every time,
    /// and <c>prompt=none</c> — a promise to show the user nothing — is answered
    /// <c>consent_required</c> for it. The client is resolved here, at the point of use, so a
    /// registration that vanished or stopped validating since the request was accepted ends the
    /// request rather than being remembered as it was.
    /// </remarks>
    public async Task<IResult> ContinueAsync(HttpContext context, AuthorizationRequestContext requestContext)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(requestContext);

        var client = await _flow.ResolveClientAsync(context, requestContext, context.RequestAborted).ConfigureAwait(false);
        if (client is null)
        {
            // The redirect URI was authenticated against a registration that no longer answers,
            // so nothing is sent there.
            _flow.Clear(context);
            return _localError.Render(
                context,
                AuthorizeRequestErrors.InvalidRequest,
                "The client that sent the authorization request is no longer registered.");
        }

        if (!client.RequireConsent)
            return PreAlphaNotImplementedResult.Result;

        if (requestContext.Prompts.Contains(PromptValue.None))
        {
            return ClientError(
                context,
                requestContext,
                AuthorizeRequestErrors.ConsentRequired,
                "The request specified prompt=none but the user's consent is required.");
        }

        if (_options.Value.AuthorizationEndpoint.Interaction.ConsentPath is not { } consentPath)
        {
            // A configuration gap, reported where a developer is looking — the client's error
            // page and the server log — since the redirect target is authenticated by now.
            _logger.LogError(
                "Client {ClientId} requires consent but AuthorizationEndpoint.Interaction.ConsentPath is not " +
                "configured. Configure the consent page, or set RequireConsent to false on the registration.",
                client.ClientId);

            return ClientError(
                context,
                requestContext,
                AuthorizeRequestErrors.ServerError,
                "The authorization server is not configured to obtain the user's consent.");
        }

        return Results.Redirect(InteractionHandoff.BuildRedirectUrl(consentPath, requestContext.Id));
    }

    /// <summary>
    /// Terminal. Records the user's consent on the interaction context and continues to code
    /// issuance.
    /// </summary>
    public async Task CompleteConsentAsync(
        HttpContext context,
        AuthorizationRequestContext requestContext,
        IReadOnlyList<string> grantedScopes)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(requestContext);
        ArgumentNullException.ThrowIfNull(grantedScopes);

        context.Response.Headers.CacheControl = "no-store";

        var consented = _flow.RecordConsent(requestContext, grantedScopes);

        var result = _flow.TryPersist(context, consented)
            ? PreAlphaNotImplementedResult.Result
            : FailTooLarge(context);

        await WriteAsync(context, result).ConfigureAwait(false);
    }

    private IResult FailTooLarge(HttpContext context)
    {
        _flow.Clear(context);
        return _localError.Render(context, AuthorizeRequestErrors.InvalidRequest, TooLarge);
    }

    /// <summary>
    /// Terminal. Starts the external round trip for one provider: activates its handler and
    /// challenges it with properties the framework wrote — the return address
    /// <c>/connect/resume</c> carrying the interaction identifier, and the identifier and the
    /// provider stamped into the properties, so the ticket the provider hands back names the
    /// interaction and provider it was issued for whatever the handler did with the state it was
    /// given.
    /// </summary>
    public async Task ChallengeAsync(HttpContext context, AuthorizationRequestContext requestContext, ProviderRegistration registration)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(requestContext);
        ArgumentNullException.ThrowIfNull(registration);

        context.Response.Headers.CacheControl = "no-store";

        var resume = ResumeEndpoint.RouteFor(EndpointRouteHelper.GetIssuerUri(_options));
        var properties = new AuthenticationProperties
        {
            RedirectUri = InteractionHandoff.BuildRedirectUrl(resume, requestContext.Id),
        };
        properties.Items[ExternalTicket.InteractionIdItem] = requestContext.Id;
        properties.Items[ExternalTicket.ChallengedProviderItem] = registration.Name;

        var handler = await _activator.ActivateAsync(context, registration).ConfigureAwait(false);
        await handler.ChallengeAsync(properties).ConfigureAwait(false);
        await context.Response.StartAsync().ConfigureAwait(false);
    }

    /// <summary>
    /// Terminal. Parks <paramref name="principal"/> for the interaction and sends the user to
    /// <paramref name="path"/> — validated by the caller — carrying the interaction identifier.
    /// </summary>
    public async Task ParkAsync(
        HttpContext context,
        AuthorizationRequestContext requestContext,
        ProviderRegistration registration,
        ClaimsPrincipal principal,
        PathString path)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(requestContext);
        ArgumentNullException.ThrowIfNull(registration);
        ArgumentNullException.ThrowIfNull(principal);

        context.Response.Headers.CacheControl = "no-store";

        await _flow.ParkPendingAsync(context, principal, requestContext.Id, registration.Name).ConfigureAwait(false);
        await WriteAsync(context, Results.Redirect(InteractionHandoff.BuildRedirectUrl(path.Value!, requestContext.Id)))
            .ConfigureAwait(false);
    }

    private static async Task WriteAsync(HttpContext context, IResult result)
    {
        await result.ExecuteAsync(context).ConfigureAwait(false);
        await context.Response.StartAsync().ConfigureAwait(false);
    }
}
