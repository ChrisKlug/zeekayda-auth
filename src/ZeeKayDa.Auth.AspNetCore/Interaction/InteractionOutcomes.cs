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
/// The ways an interaction step ends, shared by every endpoint and page service that ends one.
/// Destinations come from validated state, never from request input.
/// </summary>
/// <remarks>
/// Terminal outcomes also <em>commit</em> the response: an uncommitted redirect could be silently
/// replaced by a result the host page returns next, which for a deny is an open redirect.
/// </remarks>
internal sealed class InteractionOutcomes(
    AuthorizationFlow flow,
    AuthorizationResponses responses,
    ProviderHandlerActivator activator,
    ProviderRegistry providers,
    AuthorizationCodeIssuer issuer,
    ProviderChallengeHook challengeHook,
    IOptions<AuthorizationServerOptions> options,
    SanitizingLogger<InteractionOutcomes> logger)
{
    /// <summary>What the client is told when the interaction store refused to hold its request.</summary>
    internal const string CouldNotStoreRequest = "The authorization server could not store the authorization request.";

    /// <summary>What the user is told when the request is larger than the interaction store may hold.</summary>
    internal const string TooLarge = "The authorization request is too large to process.";

    private const string NotTheHintedUser = "The user who signed in is not the user the id_token_hint names.";

    /// <summary>An error that must not reach the client: the host's error page, or the framework's minimal one.</summary>
    public IResult LocalError(HttpContext context, string error, string description) =>
        responses.Local(context, error, description);

    /// <summary>An error at a redirect URI authenticated in phase 1, with no stored interaction to discard.</summary>
    public IResult ClientError(string redirectUri, string error, string description, string? state) =>
        responses.ErrorAtClient(redirectUri, error, description, state);

    /// <summary>An error at the stored context's redirect URI, discarding the interaction first.</summary>
    public async Task<IResult> ClientErrorAsync(HttpContext context, AuthorizationRequestContext requestContext, string error, string description)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(requestContext);

        await flow.ClearAsync(context, requestContext.Id).ConfigureAwait(false);
        return responses.ErrorAtClient(requestContext.RedirectUri, error, description, requestContext.State);
    }

    /// <summary>
    /// Terminal. Ends the request with <c>access_denied</c>, discarding the interaction and any
    /// principal parked for it.
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

        await flow.ClaimCompletionAsync(context, requestContext).ConfigureAwait(false);

        // The principal first, while the binding that addresses it is still in hand.
        await DiscardPendingAsync(context, requestContext.Id).ConfigureAwait(false);
        await flow.ClearAsync(context, requestContext.Id).ConfigureAwait(false);

        await WriteAsync(context, await DeniedAtClientAsync(context, requestContext, denial).ConfigureAwait(false))
            .ConfigureAwait(false);
    }

    /// <summary>A refusal at the external provider, answered as <see cref="ClientErrorAsync"/> answers an error.</summary>
    public async Task<IResult> DeniedAtClientAfterClearingAsync(HttpContext context, AuthorizationRequestContext requestContext, Denial denial)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(requestContext);

        await flow.ClearAsync(context, requestContext.Id).ConfigureAwait(false);
        return await DeniedAtClientAsync(context, requestContext, denial).ConfigureAwait(false);
    }

    /// <summary>
    /// The refusal's redirect, with its <c>zkd_error</c> when the client opted in; local when the
    /// client's registration no longer vouches for the redirect URI.
    /// </summary>
    private async Task<IResult> DeniedAtClientAsync(HttpContext context, AuthorizationRequestContext requestContext, Denial denial)
    {
        var client = await flow.ResolveClientAsync(context, requestContext, context.RequestAborted).ConfigureAwait(false);
        if (client is null)
            return responses.Local(context, AuthorizeRequestErrors.InvalidRequest, AuthorizationCodeIssuer.ClientNoLongerAnswers);

        return responses.DeniedAtClient(requestContext.RedirectUri, denial, client.EnableZkdErrorCodes, requestContext.State);
    }

    /// <summary>
    /// Best-effort: the claim is already taken, so a store fault here must not turn a decided denial
    /// into a failed response a retry cannot repeat. The entry becomes unreachable with the binding.
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
    /// Terminal. Promotes <paramref name="signIn"/> to the SSO session, records it on the
    /// interaction, and continues the flow; the caller has already dealt with anything parked.
    /// A user other than the one the request's <c>id_token_hint</c> names is refused with
    /// <c>login_required</c> instead, and the session is left as it was.
    /// </summary>
    public async Task CompleteSignInAsync(HttpContext context, AuthorizationRequestContext requestContext, SignIn signIn)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(requestContext);
        ArgumentNullException.ThrowIfNull(signIn);

        // A client that skips consent gets its code in this response.
        context.Response.Headers.CacheControl = "no-store";

        if (!AuthorizationFlow.IsRequiredSubject(requestContext.RequiredSubject, SsoSession.SubjectOf(signIn.Principal)))
        {
            var refusal = await ClientErrorAsync(context, requestContext, AuthorizeRequestErrors.LoginRequired, NotTheHintedUser)
                .ConfigureAwait(false);
            await WriteAsync(context, refusal).ConfigureAwait(false);
            return;
        }

        var state = await flow.PromoteAsync(context, signIn.Principal, signIn.AuthenticationMethods).ConfigureAwait(false);

        var authenticated = requestContext with
        {
            SsoSessionId = state.SessionId,
            Subject = state.Subject,
            AuthTime = state.AuthTime,
            Amr = state.Amr,
            ProviderScheme = signIn.ProviderScheme,

            // Decided by whoever signed in earlier on this interaction, not by this user.
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
            // The session stands; only this authorization request fails.
            logger.LogError(ex, "Storing the authenticated authorization request for client {ClientId} failed.", requestContext.ClientId);

            result = await ClientErrorAsync(context, requestContext, AuthorizeRequestErrors.ServerError, CouldNotStoreRequest).ConfigureAwait(false);
        }

        await WriteAsync(context, result).ConfigureAwait(false);
    }

    /// <summary>
    /// The step after authentication: the consent page when the client requires consent or the
    /// request says <c>prompt=consent</c>, else code issuance. Not terminal.
    /// </summary>
    /// <remarks>
    /// No grant is remembered, so a client that requires consent is asked every time, and
    /// <c>prompt=none</c> is answered <c>consent_required</c> for it (OIDC Core §3.1.2.6).
    /// </remarks>
    public async Task<IResult> ContinueAsync(HttpContext context, AuthorizationRequestContext requestContext)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(requestContext);

        var client = await flow.ResolveClientAsync(context, requestContext, context.RequestAborted).ConfigureAwait(false);
        if (client is null)
        {
            await flow.ClearAsync(context, requestContext.Id).ConfigureAwait(false);
            return responses.Local(context, AuthorizeRequestErrors.InvalidRequest, AuthorizationCodeIssuer.ClientNoLongerAnswers);
        }

        var consentPromptRequested = requestContext.Prompts.Contains(PromptValue.Consent);
        if (!client.RequireConsent && !consentPromptRequested)
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
                // Not a configuration gap: the host has no consent page because its clients opt out.
                return await ClientErrorAsync(
                    context,
                    requestContext,
                    AuthorizeRequestErrors.ConsentRequired,
                    "The request specified prompt=consent but the authorization server has no consent page.").ConfigureAwait(false);
            }

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
    /// Terminal. Issues the code with the user's consent recorded on it; the decision itself is
    /// never persisted for a later request.
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
    /// Terminal. Challenges one provider, returning to <c>/connect/resume</c>, with the interaction
    /// and provider stamped into properties the returned ticket carries whatever the handler does —
    /// or, when <see cref="ProviderOptions.OnProviderChallenge"/> does not let it proceed, answers
    /// the client with the error instead.
    /// </summary>
    public async Task ChallengeAsync(HttpContext context, AuthorizationRequestContext requestContext, ProviderRegistration registration)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(requestContext);
        ArgumentNullException.ThrowIfNull(registration);

        context.Response.Headers.CacheControl = "no-store";

        var properties = new AuthenticationProperties();
        StampRoundTrip(properties, requestContext, registration);

        if (await challengeHook.RefusalAsync(context, requestContext, registration, properties).ConfigureAwait(false) is { } refusal)
        {
            var error = await ClientErrorAsync(context, requestContext, refusal.Error, refusal.Description).ConfigureAwait(false);
            await WriteAsync(context, error).ConfigureAwait(false);
            return;
        }

        // The hook may have written over them.
        StampRoundTrip(properties, requestContext, registration);

        if (requestContext.ProviderAttempt is not null)
            await flow.UpdateAsync(context, requestContext with { ProviderAttempt = null }).ConfigureAwait(false);

        // Only a challenge from the login page has a page to come back to.
        if (ReturnsToLoginPage)
            ProviderChallengeCookie.Issue(context, EndpointRouteHelper.GetIssuerUri(options), registration, requestContext);

        var handler = await activator.ActivateAsync(context, registration).ConfigureAwait(false);
        await handler.ChallengeAsync(properties).ConfigureAwait(false);
        await CommitAsync(context).ConfigureAwait(false);
    }

    /// <summary>
    /// What brings the user back to this interaction through <c>/connect/resume</c>, with the
    /// ticket lifetime left to the external cookie: these properties become its ticket's.
    /// </summary>
    private void StampRoundTrip(AuthenticationProperties properties, AuthorizationRequestContext requestContext, ProviderRegistration registration)
    {
        var resume = ResumeEndpoint.RouteFor(EndpointRouteHelper.GetIssuerUri(options));
        properties.RedirectUri = InteractionHandoff.BuildRedirectUrl(resume, requestContext.Id);
        properties.Items[ExternalTicket.InteractionIdItem] = requestContext.Id;
        properties.Items[ExternalTicket.ChallengedProviderItem] = registration.Name;

        properties.IssuedUtc = null;
        properties.ExpiresUtc = null;
        properties.IsPersistent = false;
        properties.AllowRefresh = null;
    }

    /// <summary>
    /// Whether a provider that does not sign the user in returns them to the login page; false
    /// when the authorization endpoint challenges the single provider itself.
    /// </summary>
    public bool ReturnsToLoginPage => LoginPage is not null;

    private string? LoginPage =>
        LoginDispatch.LoginPageFor(options.Value.AuthorizationEndpoint.Interaction, providers.Count);

    /// <summary>
    /// Back to the login page after a provider trip that did not sign the user in, recording the
    /// outcome best-effort for the page to show. Not terminal; the client is told nothing.
    /// </summary>
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

    /// <summary>Terminal. Parks <paramref name="principal"/> and sends the user to the caller-validated <paramref name="path"/>.</summary>
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

    /// <summary>Starts the response and marks it committed, so MVC skips the host handler's own result.</summary>
    private static async Task CommitAsync(HttpContext context)
    {
        await context.Response.StartAsync().ConfigureAwait(false);
        TerminalResponse.MarkCommitted(context);
    }
}

/// <summary>What a completed sign-in promotes; <c>ProviderScheme</c> is <see langword="null"/> for a local sign-in.</summary>
internal sealed record SignIn(ClaimsPrincipal Principal, IReadOnlyList<string> AuthenticationMethods, string? ProviderScheme);
