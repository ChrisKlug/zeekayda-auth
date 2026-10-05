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
/// sign-in, a challenge to an external provider, a return to the login page from one, and a
/// parked principal sent on to a host page.
/// </summary>
/// <remarks>
/// <para>
/// The terminal outcomes write <em>and commit</em> the response. Executing a redirect result sets
/// the status and <c>Location</c> without flushing, leaving <see cref="HttpResponse.HasStarted"/>
/// false, so a host page that returns a result of its own after calling a terminal method would
/// silently replace both — which for a deny is the open redirect the interaction identifier
/// exists to prevent, written in host code where nothing validates it. Starting the response
/// commits the headers and turns that mistake into an exception the first time the page runs.
/// Under MVC, <see cref="TerminalInteractionResultFilter"/> goes one further and skips whatever
/// result follows, so a Razor Pages handler can end with a plain <c>await</c>.
/// </para>
/// <para>
/// Every outcome that leaves the interaction takes the destination from validated state — the
/// decrypted context, a registered provider — never from request input.
/// </para>
/// </remarks>
internal sealed class InteractionOutcomes(
    AuthorizationFlow flow,
    AuthorizationResponses responses,
    ProviderHandlerActivator activator,
    ProviderRegistry providers,
    AuthorizationCodeIssuer issuer,
    IOptions<AuthorizationServerOptions> options,
    SanitizingLogger<InteractionOutcomes> logger)
{
    /// <summary>What the client is told when the interaction store refused to hold its request.</summary>
    internal const string CouldNotStoreRequest = "The authorization server could not store the authorization request.";

    /// <summary>What the user is told when the request is larger than the interaction store may hold.</summary>
    internal const string TooLarge = "The authorization request is too large to process.";

    /// <summary>An error that must not reach the client: the host's error page, or the framework's minimal one.</summary>
    public IResult LocalError(HttpContext context, string error, string description) =>
        responses.Local(context, error, description);

    /// <summary>
    /// An error at a redirect URI authenticated in phase 1, for a request whose interaction
    /// context was never written or is cleared by the caller.
    /// </summary>
    public IResult ClientError(string redirectUri, string error, string description, string? state) =>
        responses.ErrorAtClient(redirectUri, error, description, state);

    /// <summary>
    /// An error at the client's registered redirect URI, read out of the stored context. The
    /// interaction is discarded first: a request that ends in an error is not resumed later.
    /// </summary>
    public async Task<IResult> ClientErrorAsync(HttpContext context, AuthorizationRequestContext requestContext, string error, string description)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(requestContext);

        await flow.ClearAsync(context, requestContext.Id).ConfigureAwait(false);
        return responses.ErrorAtClient(requestContext.RedirectUri, error, description, requestContext.State);
    }

    /// <summary>
    /// Terminal. Ends the request with <c>access_denied</c> at the client's registered redirect
    /// URI, discarding the interaction and any principal parked for it. No session is promoted
    /// and none is read.
    /// </summary>
    /// <exception cref="NothingToContinueException">
    /// Another response — a grant, a sign-in that issued, or an earlier denial — completed the
    /// interaction first, or it expired while this response was being prepared.
    /// </exception>
    public async Task DenyAsync(HttpContext context, AuthorizationRequestContext requestContext, Denial denial)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(requestContext);

        context.Response.Headers.CacheControl = "no-store";

        // A denial competes for the interaction's one terminal outcome exactly as issuance does:
        // a grant and a deny that both resolved the request alive must not end as a code and an
        // access_denied both delivered to the client.
        await flow.ClaimCompletionAsync(context, requestContext).ConfigureAwait(false);

        // Discarded before the response is written, so a denied request cannot be resumed by a
        // later sign-in picking the context back up — nor by a parked principal bound to it. The
        // principal goes first, while the binding that addresses it is still in hand.
        await DiscardPendingAsync(context, requestContext.Id).ConfigureAwait(false);
        await flow.ClearAsync(context, requestContext.Id).ConfigureAwait(false);

        await WriteAsync(context, await DeniedAtClientAsync(context, requestContext, denial).ConfigureAwait(false))
            .ConfigureAwait(false);
    }

    /// <summary>
    /// An <c>access_denied</c> refusal at the client's registered redirect URI, outside an
    /// interaction step — a refusal at the external provider — discarding the interaction first,
    /// as <see cref="ClientErrorAsync"/> does.
    /// </summary>
    public async Task<IResult> DeniedAtClientAfterClearingAsync(HttpContext context, AuthorizationRequestContext requestContext, Denial denial)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(requestContext);

        await flow.ClearAsync(context, requestContext.Id).ConfigureAwait(false);
        return await DeniedAtClientAsync(context, requestContext, denial).ConfigureAwait(false);
    }

    /// <summary>
    /// The refusal's redirect, with its <c>zkd_error</c> when the client opted in. The registration is
    /// read again here, as at every step: one that vanished, stopped validating or dropped the
    /// request's redirect URI since the request was accepted ends it locally, and nothing is sent
    /// to that URI.
    /// </summary>
    private async Task<IResult> DeniedAtClientAsync(HttpContext context, AuthorizationRequestContext requestContext, Denial denial)
    {
        var client = await flow.ResolveClientAsync(context, requestContext, context.RequestAborted).ConfigureAwait(false);
        if (client is null)
            return responses.Local(context, AuthorizeRequestErrors.InvalidRequest, AuthorizationCodeIssuer.ClientNoLongerAnswers);

        return responses.DeniedAtClient(requestContext.RedirectUri, denial, client.EnableZkdErrorCodes, requestContext.State);
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
            await flow.ConsumePendingAsync(context, interactionId).ConfigureAwait(false);
        }
        catch (ZeeKayDaStoreException ex)
        {
            logger.LogError(ex, "Discarding the external principal parked for a denied interaction failed; the entry is left to expire.");
        }
    }

    /// <summary>
    /// Terminal. Promotes the principal in <paramref name="signIn"/> to the SSO session, records
    /// the authentication on the interaction context, and continues the flow. Nothing parked for
    /// the interaction is touched: the caller has already taken or discarded it, and says which
    /// provider, if any, to record.
    /// </summary>
    /// <remarks>
    /// The session and the authenticated context are written before the flow continues, so the
    /// consent page reads a request that already knows who answered it.
    /// </remarks>
    public async Task CompleteSignInAsync(HttpContext context, AuthorizationRequestContext requestContext, SignIn signIn)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(requestContext);
        ArgumentNullException.ThrowIfNull(signIn);

        // A sign-in for a client that skips consent ends with the code in this response, and a
        // cached sign-in response is a stolen one.
        context.Response.Headers.CacheControl = "no-store";

        var state = await flow.PromoteAsync(context, signIn.Principal, signIn.AuthenticationMethods).ConfigureAwait(false);

        var authenticated = requestContext with
        {
            SsoSessionId = state.SessionId,
            Subject = state.Subject,
            AuthTime = state.AuthTime,
            Amr = state.Amr,
            ProviderScheme = signIn.ProviderScheme,

            // A decision recorded by whoever signed in earlier on this interaction is theirs, not
            // this sign-in's: the consent page asks again.
            GrantedScopes = null,
            ConsentedAt = null,
            ProviderAttempt = null,
        };

        IResult result;
        try
        {
            await flow.UpdateAsync(context, authenticated).ConfigureAwait(false);
            result = await ContinueAsync(context, authenticated).ConfigureAwait(false);
        }
        catch (ZeeKayDaStoreException ex)
        {
            // The session is established either way — what cannot continue is this authorization
            // request. The client learns the server failed; the operator learns which store
            // operation did, through the sanitizing logger.
            logger.LogError(ex, "Storing the authenticated authorization request for client {ClientId} failed.", requestContext.ClientId);

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

        var client = await flow.ResolveClientAsync(context, requestContext, context.RequestAborted).ConfigureAwait(false);
        if (client is null)
        {
            // The redirect URI was authenticated against a registration that no longer answers,
            // so nothing is sent there.
            await flow.ClearAsync(context, requestContext.Id).ConfigureAwait(false);
            return responses.Local(context, AuthorizeRequestErrors.InvalidRequest, AuthorizationCodeIssuer.ClientNoLongerAnswers);
        }

        var asked = requestContext.Prompts.Contains(PromptValue.Consent);
        if (!client.RequireConsent && !asked)
            return await issuer.IssueAsync(context, requestContext, client).ConfigureAwait(false);

        if (requestContext.Prompts.Contains(PromptValue.None))
        {
            return await ClientErrorAsync(
                context,
                requestContext,
                AuthorizeRequestErrors.ConsentRequired,
                "The request specified prompt=none but the user's consent is required.").ConfigureAwait(false);
        }

        if (options.Value.AuthorizationEndpoint.Interaction.ConsentPath is not { } consentPath)
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
            logger.LogError(
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
        IClient client,
        IReadOnlyList<string> grantedScopes)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(requestContext);
        ArgumentNullException.ThrowIfNull(client);
        ArgumentNullException.ThrowIfNull(grantedScopes);

        context.Response.Headers.CacheControl = "no-store";

        var consented = flow.RecordConsent(requestContext, grantedScopes);
        var result = await issuer.IssueAsync(context, consented, client).ConfigureAwait(false);

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

        // What the last trip to a provider ended in is no longer news once the user sets out again.
        if (requestContext.ProviderAttempt is not null)
            await flow.UpdateAsync(context, requestContext with { ProviderAttempt = null }).ConfigureAwait(false);

        var resume = ResumeEndpoint.RouteFor(EndpointRouteHelper.GetIssuerUri(options));
        var properties = new AuthenticationProperties
        {
            RedirectUri = InteractionHandoff.BuildRedirectUrl(resume, requestContext.Id),
        };
        properties.Items[ExternalTicket.InteractionIdItem] = requestContext.Id;
        properties.Items[ExternalTicket.ChallengedProviderItem] = registration.Name;
        // Only a challenge from the login page has a page to come back to.
        if (ReturnsToLoginPage)
            ProviderChallengeCookie.Issue(context, EndpointRouteHelper.GetIssuerUri(options), registration, requestContext);

        var handler = await activator.ActivateAsync(context, registration).ConfigureAwait(false);
        await handler.ChallengeAsync(properties).ConfigureAwait(false);
        await CommitAsync(context).ConfigureAwait(false);
    }

    /// <summary>
    /// Whether a provider challenge is issued from the login page and returns there when it does
    /// not sign the user in — <see langword="false"/> when the authorization endpoint challenges the
    /// one provider itself. Configuration, frozen at startup.
    /// </summary>
    public bool ReturnsToLoginPage => LoginPage is not null;

    private string? LoginPage =>
        LoginDispatch.LoginPageFor(options.Value.AuthorizationEndpoint.Interaction, providers.Count);

    /// <summary>
    /// Sends the user back to the login page after a trip to <paramref name="registration"/> that
    /// did not sign them in, recording how it ended on the interaction for the page to read. The
    /// interaction stays alive and the client is told nothing. Not terminal — the caller writes
    /// the result.
    /// </summary>
    /// <remarks>
    /// A store that cannot record the outcome still sends the user back: the page then shows an
    /// ordinary sign-in, which is a lost message, not a lost sign-in.
    /// </remarks>
    /// <exception cref="InvalidOperationException">There is no login page: <see cref="ReturnsToLoginPage"/> is false.</exception>
    public async Task<IResult> ReturnToLoginAsync(
        HttpContext context,
        AuthorizationRequestContext requestContext,
        ProviderRegistration registration,
        ProviderReturnOutcome outcome)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(requestContext);
        ArgumentNullException.ThrowIfNull(registration);

        var loginPath = LoginPage
            ?? throw new InvalidOperationException("There is no login page to return to; check ReturnsToLoginPage first.");
        var attempt = new ProviderAttempt(registration.Name, Declined: outcome == ProviderReturnOutcome.Declined);

        try
        {
            await flow.UpdateAsync(context, requestContext with { ProviderAttempt = attempt }).ConfigureAwait(false);
        }
        catch (ZeeKayDaStoreException ex)
        {
            logger.LogError(ex, "Recording the provider outcome for client {ClientId} failed; the login page will not show it.", requestContext.ClientId);
        }

        ProviderChallengeCookie.Clear(context, EndpointRouteHelper.GetIssuerUri(options), registration, requestContext.Id);
        return Results.Redirect(InteractionHandoff.BuildRedirectUrl(loginPath, requestContext.Id));
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

        await flow.ParkPendingAsync(context, new PendingTicket(principal, registration.Name), requestContext).ConfigureAwait(false);
        await WriteAsync(context, Results.Redirect(InteractionHandoff.BuildRedirectUrl(path.Value!, requestContext.Id)))
            .ConfigureAwait(false);
    }

    private static async Task WriteAsync(HttpContext context, IResult result)
    {
        await result.ExecuteAsync(context).ConfigureAwait(false);
        await CommitAsync(context).ConfigureAwait(false);
    }

    /// <summary>
    /// Starts the response and records that a terminal outcome did, which is what lets MVC skip
    /// the result a host handler would otherwise execute next.
    /// </summary>
    private static async Task CommitAsync(HttpContext context)
    {
        await context.Response.StartAsync().ConfigureAwait(false);
        TerminalResponse.MarkCommitted(context);
    }
}

/// <summary>
/// What a completed sign-in promotes: the principal the session holds, how the user proved who
/// they are, and the external provider that authenticated them, <see langword="null"/> for a
/// local sign-in.
/// </summary>
internal sealed record SignIn(ClaimsPrincipal Principal, IReadOnlyList<string> AuthenticationMethods, string? ProviderScheme);
