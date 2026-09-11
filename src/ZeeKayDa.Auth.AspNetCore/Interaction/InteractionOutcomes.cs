using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using ZeeKayDa.Auth.AspNetCore.Endpoints;
using ZeeKayDa.Auth.AspNetCore.Providers;
using ZeeKayDa.Auth.Authorization;
using ZeeKayDa.Auth.Clients;
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
    /// <summary>What the client is told when the interaction store refused to hold its request.</summary>
    internal const string CouldNotStoreRequest = "The authorization server could not store the authorization request.";

    /// <summary>What the user is told when the request is larger than the interaction store may hold.</summary>
    internal const string TooLarge = "The authorization request is too large to process.";

    /// <summary>
    /// What a refusal after the provider tells the client, whether the host's handler or its page
    /// refused. Names the stage, as the sign-in page's cancellation does, so a client can tell the
    /// two apart; framework-owned, so nothing a host or a provider said reaches the client,
    /// browser history or proxy logs.
    /// </summary>
    internal const string DeniedAfterProvider = "The sign-in at the external identity provider was not accepted.";

    private readonly AuthorizationFlow _flow;
    private readonly AuthorizationResponses _responses;
    private readonly ProviderHandlerActivator _activator;
    private readonly AuthorizationCodeIssuer _issuer;
    private readonly IOptions<AuthorizationServerOptions> _options;
    private readonly ISanitizingLogger<InteractionOutcomes> _logger;

    public InteractionOutcomes(
        AuthorizationFlow flow,
        AuthorizationResponses responses,
        ProviderHandlerActivator activator,
        AuthorizationCodeIssuer issuer,
        IOptions<AuthorizationServerOptions> options,
        ISanitizingLogger<InteractionOutcomes> logger)
    {
        ArgumentNullException.ThrowIfNull(flow);
        ArgumentNullException.ThrowIfNull(responses);
        ArgumentNullException.ThrowIfNull(activator);
        ArgumentNullException.ThrowIfNull(issuer);
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(logger);

        _flow = flow;
        _responses = responses;
        _activator = activator;
        _issuer = issuer;
        _options = options;
        _logger = logger;
    }

    /// <summary>An error that must not reach the client: the host's error page, or the framework's minimal one.</summary>
    public IResult LocalError(HttpContext context, string error, string description) =>
        _responses.Local(context, error, description);

    /// <summary>
    /// An error at a redirect URI authenticated in phase 1, for a request whose interaction
    /// context was never written or is cleared by the caller.
    /// </summary>
    public IResult ClientError(string redirectUri, string error, string description, string? state) =>
        _responses.ErrorAtClient(redirectUri, error, description, state);

    /// <summary>
    /// An error at the client's registered redirect URI, read out of the stored context. The
    /// interaction is discarded first: a request that ends in an error is not resumed later.
    /// </summary>
    public async Task<IResult> ClientErrorAsync(HttpContext context, AuthorizationRequestContext requestContext, string error, string description)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(requestContext);

        await _flow.ClearAsync(context, requestContext.Id).ConfigureAwait(false);
        return _responses.ErrorAtClient(requestContext.RedirectUri, error, description, requestContext.State);
    }

    /// <summary>
    /// Terminal. Ends the request with <c>access_denied</c> at the client's registered redirect
    /// URI, discarding the interaction and any principal parked for it. No session is promoted
    /// and none is read.
    /// </summary>
    /// <exception cref="ZeeKayDaInteractionException">
    /// Another response — a grant, a sign-in that issued, or an earlier denial — completed the
    /// interaction first, or it expired while this response was being prepared.
    /// </exception>
    public async Task DenyAsync(HttpContext context, AuthorizationRequestContext requestContext, string description)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(requestContext);

        context.Response.Headers.CacheControl = "no-store";

        // A denial competes for the interaction's one terminal outcome exactly as issuance does:
        // a grant and a deny that both resolved the request alive must not end as a code and an
        // access_denied both delivered to the client.
        await _flow.ClaimCompletionAsync(context, requestContext).ConfigureAwait(false);

        // Discarded before the response is written, so a denied request cannot be resumed by a
        // later sign-in picking the context back up — nor by a parked principal bound to it. The
        // principal goes first, while the binding that addresses it is still in hand.
        await DiscardPendingAsync(context, requestContext.Id).ConfigureAwait(false);
        await _flow.ClearAsync(context, requestContext.Id).ConfigureAwait(false);

        await WriteAsync(
                context,
                _responses.ErrorAtClient(requestContext.RedirectUri, AuthorizeRequestErrors.AccessDenied, description, requestContext.State))
            .ConfigureAwait(false);
    }

    /// <summary>
    /// Removes a principal parked for a denied interaction, best-effort. A denial has no use for
    /// the principal, and the claim on the interaction is already taken by the time this runs: a
    /// store that cannot read the entry must not turn a decided denial into a failed response
    /// that the client never sees and a retry cannot repeat. The binding goes next, after which
    /// the entry is unreachable and left to its lifetime.
    /// </summary>
    private async Task DiscardPendingAsync(HttpContext context, string interactionId)
    {
        try
        {
            await _flow.ConsumePendingAsync(context, interactionId).ConfigureAwait(false);
        }
        catch (ZeeKayDaStoreException ex)
        {
            _logger.LogError(ex, "Discarding the external principal parked for a denied interaction failed; the entry is left to expire.");
        }
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

        var pending = await _flow.ConsumePendingAsync(context, requestContext.Id).ConfigureAwait(false);

        await CompleteSignInCoreAsync(context, requestContext, principal, authenticationMethods, providerScheme ?? pending?.Provider)
            .ConfigureAwait(false);
    }

    /// <summary>
    /// Terminal. As <see cref="CompleteSignInAsync"/>, for a caller that has already taken the
    /// parked principal out of the store: nothing is consumed here, so a principal parked after
    /// the caller's take is left where it is, and the provider recorded is the one that parked
    /// what the caller took.
    /// </summary>
    public Task CompleteTakenSignInAsync(
        HttpContext context,
        AuthorizationRequestContext requestContext,
        ClaimsPrincipal principal,
        IReadOnlyList<string> authenticationMethods,
        PendingTicket taken)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(requestContext);
        ArgumentNullException.ThrowIfNull(principal);
        ArgumentNullException.ThrowIfNull(authenticationMethods);
        ArgumentNullException.ThrowIfNull(taken);

        return CompleteSignInCoreAsync(context, requestContext, principal, authenticationMethods, taken.Provider);
    }

    private async Task CompleteSignInCoreAsync(
        HttpContext context,
        AuthorizationRequestContext requestContext,
        ClaimsPrincipal principal,
        IReadOnlyList<string> authenticationMethods,
        string? providerScheme)
    {
        // A sign-in for a client that skips consent ends with the code in this response, and a
        // cached sign-in response is a stolen one.
        context.Response.Headers.CacheControl = "no-store";

        var state = await _flow.PromoteAsync(context, principal, authenticationMethods).ConfigureAwait(false);

        var authenticated = requestContext with
        {
            SsoSessionId = state.SessionId,
            Subject = state.Subject,
            AuthTime = state.AuthTime,
            Amr = state.Amr,
            ProviderScheme = providerScheme,

            // A decision recorded by whoever signed in earlier on this interaction is theirs, not
            // this sign-in's: the consent page asks again.
            GrantedScopes = null,
            ConsentedAt = null,
        };

        IResult result;
        try
        {
            await _flow.UpdateAsync(context, authenticated).ConfigureAwait(false);
            result = await ContinueAsync(context, authenticated).ConfigureAwait(false);
        }
        catch (ZeeKayDaStoreException ex)
        {
            // The session is established either way — what cannot continue is this authorization
            // request. The client learns the server failed; the operator learns which store
            // operation did, through the sanitizing logger.
            _logger.LogError(ex, "Storing the authenticated authorization request for client {ClientId} failed.", requestContext.ClientId);

            result = await ClientErrorAsync(context, requestContext, AuthorizeRequestErrors.ServerError, CouldNotStoreRequest).ConfigureAwait(false);
        }

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
    /// <c>consent_required</c> for it. A client that opted out is still asked when its request
    /// says <c>prompt=consent</c>: the server should prompt when asked to, and must answer
    /// <c>consent_required</c> when it cannot. The client is resolved here, at the point of use,
    /// so a registration that vanished, stopped validating or dropped the request's redirect URI
    /// since the request was accepted ends the request rather than being remembered as it was.
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
            await _flow.ClearAsync(context, requestContext.Id).ConfigureAwait(false);
            return _responses.Local(context, AuthorizeRequestErrors.InvalidRequest, AuthorizationCodeIssuer.ClientNoLongerAnswers);
        }

        var asked = requestContext.Prompts.Contains(PromptValue.Consent);
        if (!client.RequireConsent && !asked)
            return await _issuer.IssueAsync(context, requestContext, client).ConfigureAwait(false);

        if (requestContext.Prompts.Contains(PromptValue.None))
        {
            return await ClientErrorAsync(
                context,
                requestContext,
                AuthorizeRequestErrors.ConsentRequired,
                "The request specified prompt=none but the user's consent is required.").ConfigureAwait(false);
        }

        if (_options.Value.AuthorizationEndpoint.Interaction.ConsentPath is not { } consentPath)
        {
            if (!client.RequireConsent)
            {
                // The client asked for a page this host deliberately does not have for its
                // opt-out clients: a refusal the client can act on, not a configuration gap.
                return await ClientErrorAsync(
                    context,
                    requestContext,
                    AuthorizeRequestErrors.ConsentRequired,
                    "The request specified prompt=consent but the authorization server has no consent page.").ConfigureAwait(false);
            }

            // A configuration gap, reported where a developer is looking — the client's error
            // page and the server log — since the redirect target is authenticated by now.
            _logger.LogError(
                "Client {ClientId} requires consent but AuthorizationEndpoint.Interaction.ConsentPath is not " +
                "configured. Configure the consent page, or set RequireConsent to false on the registration.",
                client.ClientId);

            return await ClientErrorAsync(
                context,
                requestContext,
                AuthorizeRequestErrors.ServerError,
                "The authorization server is not configured to obtain the user's consent.").ConfigureAwait(false);
        }

        return Results.Redirect(InteractionHandoff.BuildRedirectUrl(consentPath, requestContext.Id));
    }

    /// <summary>
    /// Terminal. Records the user's consent on the interaction context and issues the code to
    /// <paramref name="client"/>, the registration the consent service resolved for this
    /// request. The decision is never persisted: it is taken, the code issued and the
    /// interaction discarded in the one response, so there is no recorded grant for a later
    /// request to pick up.
    /// </summary>
    public async Task CompleteConsentAsync(
        HttpContext context,
        AuthorizationRequestContext requestContext,
        IClientMetadata client,
        IReadOnlyList<string> grantedScopes)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(requestContext);
        ArgumentNullException.ThrowIfNull(client);
        ArgumentNullException.ThrowIfNull(grantedScopes);

        context.Response.Headers.CacheControl = "no-store";

        var consented = _flow.RecordConsent(requestContext, grantedScopes);
        var result = await _issuer.IssueAsync(context, consented, client).ConfigureAwait(false);

        await WriteAsync(context, result).ConfigureAwait(false);
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

        await _flow.ParkPendingAsync(context, new PendingTicket(principal, registration.Name), requestContext).ConfigureAwait(false);
        await WriteAsync(context, Results.Redirect(InteractionHandoff.BuildRedirectUrl(path.Value!, requestContext.Id)))
            .ConfigureAwait(false);
    }

    private static async Task WriteAsync(HttpContext context, IResult result)
    {
        await result.ExecuteAsync(context).ConfigureAwait(false);
        await context.Response.StartAsync().ConfigureAwait(false);
    }
}
