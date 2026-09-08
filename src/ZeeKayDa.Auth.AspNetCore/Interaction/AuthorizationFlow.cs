using System.Security.Claims;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using ZeeKayDa.Auth.Authorization;
using ZeeKayDa.Auth.Clients;

namespace ZeeKayDa.Auth.AspNetCore.Interaction;

/// <summary>
/// The interaction state of an authorization request, and the single seam through which every
/// stage of the flow reads and writes it: the context the authorization endpoint writes, the SSO
/// session, and the principal an external provider returned that a host page is still working on.
/// </summary>
/// <remarks>
/// <para>
/// Everything here is addressed by the interaction, never by "the current request's interaction as
/// a global". Any number of interactions can be in flight in one browser, and each stage names
/// the one it is working on.
/// </para>
/// <para>
/// It is not an interface and does not want to be one. A single implementation does not justify
/// an abstraction, and an interface designed against one implementation usually fits the second
/// badly.
/// </para>
/// </remarks>
internal sealed class AuthorizationFlow
{
    private readonly AuthorizationRequestContextStore _contexts;
    private readonly SsoSession _session;
    private readonly PendingPrincipalStore _pending;
    private readonly IOptions<AuthorizationServerOptions> _options;
    private readonly TimeProvider _timeProvider;

    public AuthorizationFlow(
        AuthorizationRequestContextStore contexts,
        SsoSession session,
        PendingPrincipalStore pending,
        IOptions<AuthorizationServerOptions> options,
        TimeProvider timeProvider)
    {
        ArgumentNullException.ThrowIfNull(contexts);
        ArgumentNullException.ThrowIfNull(session);
        ArgumentNullException.ThrowIfNull(pending);
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(timeProvider);

        _contexts = contexts;
        _session = session;
        _pending = pending;
        _options = options;
        _timeProvider = timeProvider;
    }

    /// <summary>Reads the established SSO session, or <see langword="null"/> when there is none.</summary>
    public Task<SsoSessionState?> ReadSessionAsync(HttpContext context) => _session.ReadAsync(context);

    /// <summary>Establishes the SSO session for an authenticated principal.</summary>
    public Task<SsoSessionState> PromoteAsync(
        HttpContext context,
        ClaimsPrincipal principal,
        IReadOnlyList<string> authenticationMethods) =>
        _session.PromoteAsync(context, principal, authenticationMethods);

    /// <summary>
    /// Whether the request must be authenticated before it can continue: no session at all, a
    /// client asking for re-authentication with <c>prompt=login</c>, or a session older than the
    /// requested <c>max_age</c>.
    /// </summary>
    public bool NeedsAuthentication(ValidatedAuthorizeRequest request, SsoSessionState? session)
    {
        ArgumentNullException.ThrowIfNull(request);

        if (session is null || request.Prompts.Contains(PromptValue.Login))
            return true;

        // max_age=0 asks for re-authentication unconditionally, and falls out of the comparison
        // rather than needing a case of its own.
        return request.MaxAge is { } maxAge && _timeProvider.GetUtcNow() - session.AuthTime > maxAge;
    }

    /// <summary>
    /// Builds the context for a freshly validated request, carrying the authenticated session's
    /// details when the flow continues on an existing session, and nothing but protocol state
    /// when the user has yet to authenticate.
    /// </summary>
    public AuthorizationRequestContext CreateContext(
        ValidatedAuthorizeRequest request,
        SsoSessionState? session)
    {
        ArgumentNullException.ThrowIfNull(request);

        var now = _timeProvider.GetUtcNow();

        return new AuthorizationRequestContext
        {
            Id = Stores.StoreKeyGenerator.Generate(),
            ClientId = request.Client.ClientId,
            RedirectUri = request.RedirectUri,
            Scopes = request.Scopes,
            State = request.State,
            Nonce = request.Nonce,
            CodeChallenge = request.CodeChallenge,
            CodeChallengeMethod = request.CodeChallengeMethod,
            Prompts = request.Prompts,
            MaxAge = request.MaxAge,
            IssuedAt = now,
            ExpiresAt = now + AuthorizationRequestContextStore.Lifetime,
            SsoSessionId = session?.SessionId,
            Subject = session?.Subject,
            AuthTime = session?.AuthTime,
            Amr = session?.Amr,
        };
    }

    /// <summary>
    /// Whether the session this browser holds is the one that authenticated the request — the
    /// same session identifier and the same subject. False before authentication, after a
    /// sign-out, and after a sign-in as someone else.
    /// </summary>
    /// <remarks>
    /// Both values come from framework-written encrypted state, so this is an ordinary ordinal
    /// comparison: nothing here is request input whose bytes a timing difference could leak.
    /// </remarks>
    public async Task<bool> IsAuthenticatedByCurrentSessionAsync(HttpContext context, AuthorizationRequestContext requestContext)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(requestContext);

        // The subject is written by the same promotion as the session identifier, so a context
        // with the identifier has the subject too; the equality below fails for a missing one.
        if (requestContext.SsoSessionId is null)
            return false;

        var session = await ReadSessionAsync(context).ConfigureAwait(false);

        return session is not null
            && string.Equals(session.SessionId, requestContext.SsoSessionId, StringComparison.Ordinal)
            && string.Equals(session.Subject, requestContext.Subject, StringComparison.Ordinal);
    }

    /// <summary>
    /// The validated registration of the client that sent the request, or <see langword="null"/>
    /// when it is no longer registered, no longer validates, or no longer lists the redirect URI
    /// the request was accepted with — resolved at the point of use, as every endpoint resolves
    /// clients, never remembered from when the request was accepted. An operator who removes a
    /// redirect URI from a live registration means nothing more to be sent there, error included.
    /// </summary>
    /// <remarks>
    /// The resolver comes from the request's services rather than this singleton's constructor:
    /// the endpoints are constructed when they are mapped, before startup verification runs, and
    /// the client repository behind the resolver validates its registrations against the signing
    /// key ring when it is built. Taking it eagerly would make endpoint mapping the first thing to
    /// touch the ring, which is startup verification's job to do, and to refuse to do when a
    /// cheaper check has already failed.
    /// </remarks>
    public async ValueTask<IClientMetadata?> ResolveClientAsync(
        HttpContext context,
        AuthorizationRequestContext requestContext,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(requestContext);

        var clients = context.RequestServices.GetRequiredService<ValidatedClientResolver>();
        var client = await clients.FindByClientIdAsync(requestContext.ClientId, cancellationToken).ConfigureAwait(false);

        return client is not null
            && AuthorizeRedirectUriMatcher.TryMatch(requestContext.RedirectUri, client.RedirectUris, out _)
            ? client
            : null;
    }

    /// <summary>
    /// The client as a host page sees it: the identifier the request named, and the display name
    /// its registration carries today, if it still has one.
    /// </summary>
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
            ConsentedAt = _timeProvider.GetUtcNow(),
        };
    }

    /// <summary>
    /// Reads the interaction <paramref name="interactionId"/> names, if this browser started it
    /// and it is still alive.
    /// </summary>
    /// <exception cref="ZeeKayDaStoreException">The interaction store could not be read.</exception>
    public ValueTask<AuthorizationRequestContext?> ReadAsync(HttpContext context, string interactionId) =>
        _contexts.ReadAsync(context, interactionId, context.RequestAborted);

    /// <summary>
    /// Resolves the interaction this request is entitled to complete: the one the framework sent
    /// the user to a host page for, named by <c>zkd_i</c> and bound to this browser. Never "the
    /// current interaction".
    /// </summary>
    /// <exception cref="ZeeKayDaInteractionException">
    /// The request carries no <c>zkd_i</c>, or names an interaction this browser is not carrying.
    /// </exception>
    /// <exception cref="ZeeKayDaStoreException">The interaction store could not be read.</exception>
    public async ValueTask<AuthorizationRequestContext> ResolveAddressedAsync(HttpContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        var interactionId = await RequireInteractionIdAsync(context).ConfigureAwait(false);

        return await ReadAsync(context, interactionId).ConfigureAwait(false)
            ?? throw new ZeeKayDaInteractionException(
                "There is no active interaction with this identifier for this browser. The authorization " +
                "request has expired or already completed, the page was reached without going through " +
                "/connect/authorize, or the request was started in another browser.");
    }

    /// <summary>The interaction identifier the request was addressed with.</summary>
    /// <exception cref="ZeeKayDaInteractionException">The request carries no <c>zkd_i</c>.</exception>
    public static async ValueTask<string> RequireInteractionIdAsync(HttpContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        return await InteractionHandoff.ReadInteractionIdAsync(context.Request).ConfigureAwait(false)
            ?? throw new ZeeKayDaInteractionException(
                $"This request carries no '{InteractionHandoff.InteractionIdParameter}' parameter, so there " +
                "is no interaction to complete. The framework adds it to the URL it redirects the login " +
                "page to; a form that regenerates its action from routing drops it, and must pass it back " +
                $"explicitly (asp-route-{InteractionHandoff.InteractionIdParameter}).");
    }

    /// <summary>
    /// Claims the interaction's one terminal outcome for this response, or refuses. Every path that
    /// ends an interaction at the client — a code or a denial — takes the claim first, so two
    /// responses that both resolved the request alive cannot both end it. A refused claim discards
    /// the interaction: whichever way, this request has nothing left to complete.
    /// </summary>
    /// <returns>The time the claim was taken, for the outcome to be stamped with.</returns>
    /// <exception cref="ZeeKayDaInteractionException">
    /// Another response already completed, or is completing, the interaction — or it expired while
    /// this response was being prepared.
    /// </exception>
    /// <exception cref="ZeeKayDaStoreException">The authorization code store could not record the claim.</exception>
    /// <remarks>
    /// <para>
    /// The claim lives in the authorization code store, whose atomic insert every backend already
    /// has to provide; resolved per request for the reason <see cref="ResolveClientAsync"/> is.
    /// </para>
    /// <para>
    /// Expiry is checked before the claim, so a request that ran out is refused as expired rather
    /// than handing the store a claim already past its lifetime, and again after it: the claim
    /// lasts only as long as the interaction, so a response that outlived it could otherwise claim
    /// again once the first response's claim had lapsed. Two claims can both succeed only if both
    /// landed before the interaction expired, and the atomic insert already forbids that.
    /// </para>
    /// </remarks>
    public async ValueTask<DateTimeOffset> ClaimCompletionAsync(HttpContext context, AuthorizationRequestContext requestContext)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(requestContext);

        if (IsExpired(requestContext))
            await RefuseAsync(context, requestContext, ExpiredBeforeCompletion).ConfigureAwait(false);

        var store = context.RequestServices.GetRequiredService<Stores.IAuthorizationCodeStore>();
        var claimed = await store.TryClaimInteractionAsync(requestContext.Id, requestContext.ExpiresAt, context.RequestAborted).ConfigureAwait(false);

        if (!claimed)
            await RefuseAsync(context, requestContext, AlreadyCompleted).ConfigureAwait(false);

        var now = _timeProvider.GetUtcNow();
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
        _timeProvider.GetUtcNow() >= requestContext.ExpiresAt;

    private async ValueTask RefuseAsync(HttpContext context, AuthorizationRequestContext requestContext, string reason)
    {
        await ClearAsync(context, requestContext.Id).ConfigureAwait(false);
        throw new ZeeKayDaInteractionException(reason);
    }

    /// <summary>
    /// Persists a freshly accepted request, bound to this browser. Returns <see langword="false"/>
    /// when the request is larger than the interaction store may hold, in which case nothing was
    /// written and the caller must fail the request.
    /// </summary>
    /// <exception cref="ZeeKayDaStoreException">The interaction store could not be written.</exception>
    public ValueTask<bool> TryPersistAsync(HttpContext context, AuthorizationRequestContext requestContext) =>
        _contexts.TryStoreAsync(context, requestContext, _options.Value.AuthorizationEndpoint.MaxRequestContextBytes, context.RequestAborted);

    /// <summary>Replaces the stored context in place, under the binding this request carries.</summary>
    /// <exception cref="ZeeKayDaStoreException">The interaction store could not be written.</exception>
    public ValueTask UpdateAsync(HttpContext context, AuthorizationRequestContext requestContext) =>
        _contexts.UpdateAsync(context, requestContext, context.RequestAborted);

    /// <summary>
    /// Discards the interaction. Called whenever a request ends, so that a completed, failed or
    /// planted interaction is never left alive for a later sign-in to pick up. Best-effort: the
    /// binding cookie always goes; a store that refuses the removal is logged, not thrown. A
    /// principal still parked for the interaction shares that binding, so it becomes unreachable
    /// here and is left to its own lifetime.
    /// </summary>
    public ValueTask ClearAsync(HttpContext context, string interactionId) =>
        _contexts.DeleteAsync(context, interactionId, context.RequestAborted);

    /// <summary>
    /// Parks a principal an external provider returned for <paramref name="requestContext"/>'s
    /// interaction, under the binding this request carries.
    /// </summary>
    /// <exception cref="ZeeKayDaStoreException">The interaction store could not be written.</exception>
    public ValueTask ParkPendingAsync(HttpContext context, ClaimsPrincipal principal, AuthorizationRequestContext requestContext, string provider) =>
        _pending.ParkAsync(context, principal, requestContext, provider, context.RequestAborted);

    /// <summary>The parked principal bound to <paramref name="interactionId"/>, or <see langword="null"/>.</summary>
    /// <exception cref="ZeeKayDaStoreException">The interaction store could not be read.</exception>
    public ValueTask<PendingTicket?> ReadPendingAsync(HttpContext context, string interactionId, CancellationToken cancellationToken) =>
        _pending.ReadAsync(context, interactionId, cancellationToken);

    /// <summary>
    /// Reads and removes the parked principal: whichever sign-in or denial completes the
    /// interaction takes it with it. Removal is best-effort; the read is not.
    /// </summary>
    /// <exception cref="ZeeKayDaStoreException">The interaction store could not be read.</exception>
    public ValueTask<PendingTicket?> ConsumePendingAsync(HttpContext context, string interactionId) =>
        _pending.ConsumeAsync(context, interactionId, context.RequestAborted);
}
