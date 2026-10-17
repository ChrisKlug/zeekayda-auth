using System.Security.Claims;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using ZeeKayDa.Auth.Authorization;
using ZeeKayDa.Auth.Clients;

namespace ZeeKayDa.Auth.AspNetCore.Interaction;

/// <summary>
/// The one seam through which every stage reads and writes an authorization request's interaction
/// state, always addressed by interaction: one browser can have any number in flight.
/// </summary>
internal sealed class AuthorizationFlow(
    AuthorizationRequestContextStore contexts,
    SsoSession session,
    PendingPrincipalStore pending,
    IOptions<AuthorizationServerOptions> options,
    TimeProvider timeProvider)
{
    private readonly SsoSession _session = session;

    /// <summary>Reads the established SSO session, or <see langword="null"/> when there is none.</summary>
    public Task<SsoSessionState?> ReadSessionAsync(HttpContext context) => _session.ReadAsync(context);

    /// <summary>Establishes the SSO session for an authenticated subject.</summary>
    public Task<SsoSessionState> PromoteAsync(
        HttpContext context,
        SessionSubject subject,
        IReadOnlyList<string> authenticationMethods) =>
        _session.PromoteAsync(context, subject, authenticationMethods);

    /// <summary>
    /// Whether the request must be authenticated before it can continue: no session at all, a
    /// session for another user than the <c>id_token_hint</c> names, a client asking for
    /// re-authentication with <c>prompt=login</c>, or a session older than the requested <c>max_age</c>.
    /// </summary>
    public bool NeedsAuthentication(ValidatedAuthorizeRequest request, SsoSessionState? session)
    {
        ArgumentNullException.ThrowIfNull(request);

        return session is null
            || !IsRequiredSubject(request.RequiredSubject, session.Subject)
            || RequiresReauthentication(request.Prompts, request.MaxAge, session);
    }

    /// <summary>
    /// Whether <paramref name="subject"/> may answer a request requiring <paramref name="requiredSubject"/>:
    /// anyone when the request named no one (OIDC Core §3.1.2.2).
    /// </summary>
    public static bool IsRequiredSubject(string? requiredSubject, string? subject) =>
        requiredSubject is null || string.Equals(subject, requiredSubject, StringComparison.Ordinal);

    /// <summary>
    /// Whether the client demands that the user authenticate again: <c>prompt=login</c>, or a
    /// <c>max_age</c> that no <paramref name="session"/> is within, because there is none or it is
    /// older (OIDC Core §3.1.2.1).
    /// </summary>
    public bool RequiresReauthentication(IReadOnlySet<PromptValue> prompts, TimeSpan? maxAge, SsoSessionState? session)
    {
        ArgumentNullException.ThrowIfNull(prompts);

        if (prompts.Contains(PromptValue.Login))
            return true;

        return maxAge is { } limit && (session is null || IsOlderThan(session, limit));
    }

    /// <summary>The context for a freshly validated request, carrying the session it continues on, if any.</summary>
    public AuthorizationRequestContext CreateContext(
        ValidatedAuthorizeRequest request,
        SsoSessionState? session)
    {
        ArgumentNullException.ThrowIfNull(request);

        var now = timeProvider.GetUtcNow();

        return new AuthorizationRequestContext
        {
            Id = Stores.StoreKeyGenerator.Generate(),
            ClientId = request.Client.ClientId,
            RedirectUri = request.RedirectUri,
            Scopes = request.Scopes,
            State = request.State,
            Nonce = request.Nonce,
            Pkce = request.Pkce,
            Prompts = request.Prompts,
            MaxAge = request.MaxAge,
            LoginHint = request.LoginHint,
            RequiredSubject = request.RequiredSubject,
            IssuedAt = now,
            ExpiresAt = now + AuthorizationRequestContextStore.Lifetime,
            SsoSessionId = session?.SessionId,
            Subject = session?.Subject,
            AuthTime = session?.AuthTime,
            Amr = session?.Amr,
        };
    }

    /// <summary>
    /// Whether the session this browser holds, by identifier and subject, is the one that
    /// authenticated the request. Ordinal, not fixed-time: both sides are framework-encrypted state.
    /// </summary>
    public async Task<bool> IsAuthenticatedByCurrentSessionAsync(HttpContext context, AuthorizationRequestContext requestContext)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(requestContext);

        if (requestContext.SsoSessionId is null)
            return false;

        var session = await ReadSessionAsync(context).ConfigureAwait(false);

        return session is not null
            && string.Equals(session.SessionId, requestContext.SsoSessionId, StringComparison.Ordinal)
            && string.Equals(session.Subject, requestContext.Subject, StringComparison.Ordinal);
    }

    /// <summary>
    /// The client's registration as it stands now, or <see langword="null"/> when it no longer
    /// validates or no longer lists the request's redirect URI — nothing more is sent there.
    /// </summary>
    /// <remarks>
    /// From request services, not the constructor: building the resolver touches the signing key
    /// ring, which must wait for startup verification, and endpoints are built at mapping.
    /// </remarks>
    public async ValueTask<IClient?> ResolveClientAsync(
        HttpContext context,
        AuthorizationRequestContext requestContext,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(requestContext);

        var clients = context.RequestServices.GetRequiredService<ValidatedClientResolver>();
        var client = await clients.FindClientAsync(requestContext.ClientId, cancellationToken).ConfigureAwait(false);

        return client is not null
            && AuthorizeRedirectUriMatcher.TryMatch(requestContext.RedirectUri, client.RedirectUris, out _)
            ? client
            : null;
    }

    /// <summary>The client as a host page sees it: the requested identifier and today's display name.</summary>
    public async ValueTask<ClientInformation> DescribeClientAsync(
        HttpContext context,
        AuthorizationRequestContext requestContext,
        CancellationToken cancellationToken)
    {
        var client = await ResolveClientAsync(context, requestContext, cancellationToken).ConfigureAwait(false);

        return new ClientInformation(requestContext.ClientId, client?.DisplayName);
    }

    /// <summary>Records the user's consent on the context, stamped with the current time.</summary>
    public AuthorizationRequestContext RecordConsent(
        AuthorizationRequestContext requestContext,
        IReadOnlyList<string> grantedScopes)
    {
        ArgumentNullException.ThrowIfNull(requestContext);
        ArgumentNullException.ThrowIfNull(grantedScopes);

        return requestContext with
        {
            GrantedScopes = grantedScopes,
            ConsentedAt = timeProvider.GetUtcNow(),
        };
    }

    /// <summary>The interaction <paramref name="interactionId"/> names, if this browser started it and it is alive.</summary>
    /// <exception cref="ZeeKayDaStoreException">The interaction store could not be read.</exception>
    public ValueTask<AuthorizationRequestContext?> ReadAsync(HttpContext context, string interactionId) =>
        contexts.ReadAsync(context, interactionId, context.RequestAborted);

    /// <summary>The interaction this request names by <c>zkd_i</c>, bound to this browser.</summary>
    /// <exception cref="NothingToContinueException">
    /// The request carries no <c>zkd_i</c>, or names an interaction this browser is not carrying.
    /// </exception>
    /// <exception cref="ZeeKayDaStoreException">The interaction store could not be read.</exception>
    public async ValueTask<AuthorizationRequestContext> ResolveAddressedAsync(HttpContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        var interactionId = await RequireInteractionIdAsync(context).ConfigureAwait(false);

        var requestContext = await ReadAsync(context, interactionId).ConfigureAwait(false);
        if (requestContext is not null)
            return requestContext;

        // Retires the binding's secret, freeing its per-browser slot; the client hint the restart needs stays.
        await ClearAsync(context, interactionId).ConfigureAwait(false);

        throw new NothingToContinueException(
                NothingToContinueReason.NotFound,
                "There is no active interaction with this identifier for this browser. The authorization " +
                "request has expired or already completed, the page was reached without going through " +
                "/connect/authorize, or the request was started in another browser.");
    }

    /// <summary>The interaction identifier the request was addressed with.</summary>
    /// <exception cref="NothingToContinueException">The request carries no <c>zkd_i</c>.</exception>
    public static async ValueTask<string> RequireInteractionIdAsync(HttpContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        return await InteractionHandoff.ReadInteractionIdAsync(context.Request).ConfigureAwait(false)
            ?? throw new NothingToContinueException(
                NothingToContinueReason.NoInteractionId,
                $"This request carries no '{InteractionHandoff.InteractionIdParameter}' parameter, so there " +
                "is no interaction to complete. The framework adds it to the URL it redirects the login " +
                "page to; a form that regenerates its action from routing drops it, and must pass it back " +
                $"explicitly (asp-route-{InteractionHandoff.InteractionIdParameter}).");
    }

    /// <summary>
    /// Claims the interaction's one terminal outcome — a code or a denial — for this response, or
    /// discards the interaction and refuses.
    /// </summary>
    /// <returns>The time the claim was taken, for the outcome to be stamped with.</returns>
    /// <exception cref="NothingToContinueException">
    /// Another response already completed, or is completing, the interaction — or it expired while
    /// this response was being prepared.
    /// </exception>
    /// <exception cref="ZeeKayDaStoreException">The authorization code store could not record the claim.</exception>
    /// <remarks>
    /// The claim lasts only as long as the interaction, so expiry is checked after it as well as
    /// before: a response that outlived the interaction could otherwise claim again once the first
    /// claim had lapsed.
    /// </remarks>
    public async ValueTask<DateTimeOffset> ClaimCompletionAsync(HttpContext context, AuthorizationRequestContext requestContext)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(requestContext);

        if (IsExpired(requestContext))
            await RefuseAsync(context, requestContext, ExpiredBeforeCompletion).ConfigureAwait(false);

        var store = context.RequestServices.GetRequiredService<Stores.AuthorizationCodeStore>();
        var claimed = await store.TryClaimInteractionAsync(requestContext.Id, requestContext.ExpiresAt, context.RequestAborted).ConfigureAwait(false);

        if (!claimed)
            await RefuseAsync(context, requestContext, AlreadyCompleted).ConfigureAwait(false);

        var now = timeProvider.GetUtcNow();
        if (now >= requestContext.ExpiresAt)
            await RefuseAsync(context, requestContext, ExpiredBeforeCompletion).ConfigureAwait(false);

        return now;
    }

    private const string AlreadyCompleted =
        "This authorization request has already been completed by another response — an authorization " +
        "code was issued, or the request was denied. The same request was answered twice; the first " +
        "answer stands.";

    private const string ExpiredBeforeCompletion =
        "The authorization request expired before it could be completed. Start the authorization request again.";

    private bool IsExpired(AuthorizationRequestContext requestContext) =>
        timeProvider.GetUtcNow() >= requestContext.ExpiresAt;

    // max_age=0 falls out of the comparison.
    private bool IsOlderThan(SsoSessionState session, TimeSpan maxAge) =>
        timeProvider.GetUtcNow() - session.AuthTime > maxAge;

    private async ValueTask RefuseAsync(HttpContext context, AuthorizationRequestContext requestContext, string reason)
    {
        await ClearAsync(context, requestContext.Id).ConfigureAwait(false);
        throw new NothingToContinueException(NothingToContinueReason.AlreadyCompleted, reason);
    }

    /// <summary>Persists a new request, bound to this browser; <see langword="false"/> when it is too large to store.</summary>
    /// <exception cref="ZeeKayDaStoreException">The interaction store could not be written.</exception>
    public ValueTask<bool> TryPersistAsync(HttpContext context, AuthorizationRequestContext requestContext) =>
        contexts.TryStoreAsync(context, requestContext, options.Value.AuthorizationEndpoint.MaxRequestContextBytes, context.RequestAborted);

    /// <summary>Replaces the stored context in place, under the binding this request carries.</summary>
    /// <exception cref="ZeeKayDaStoreException">The interaction store could not be written.</exception>
    public ValueTask UpdateAsync(HttpContext context, AuthorizationRequestContext requestContext) =>
        contexts.UpdateAsync(context, requestContext, context.RequestAborted);

    /// <summary>
    /// Discards the interaction, and with its binding any principal parked for it. Best-effort: the
    /// binding cookie always goes; a store fault is logged.
    /// </summary>
    public ValueTask ClearAsync(HttpContext context, string interactionId) =>
        contexts.DeleteAsync(context, interactionId, context.RequestAborted);

    /// <summary>Parks a principal an external provider returned for the interaction, under this request's binding.</summary>
    /// <exception cref="ZeeKayDaStoreException">The interaction store could not be written.</exception>
    public ValueTask ParkPendingAsync(HttpContext context, PendingTicket ticket, AuthorizationRequestContext requestContext) =>
        pending.ParkAsync(context, ticket, requestContext, context.RequestAborted);

    /// <summary>The parked principal bound to <paramref name="interactionId"/>, or <see langword="null"/>.</summary>
    /// <exception cref="ZeeKayDaStoreException">The interaction store could not be read.</exception>
    public ValueTask<PendingTicket?> ReadPendingAsync(HttpContext context, string interactionId, CancellationToken cancellationToken) =>
        pending.ReadAsync(context, interactionId, cancellationToken);

    /// <summary>Reads and removes the parked principal; removal is best-effort, the read is not.</summary>
    /// <exception cref="ZeeKayDaStoreException">The interaction store could not be read.</exception>
    public ValueTask<PendingTicket?> ConsumePendingAsync(HttpContext context, string interactionId) =>
        pending.ConsumeAsync(context, interactionId, context.RequestAborted);
}
