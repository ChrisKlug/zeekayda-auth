using System.Security.Claims;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
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
/// a global". That is deliberate: replacing the cookie with a store (#603) changes what is behind
/// these methods and nothing about their callers.
/// </para>
/// <para>
/// It is not an interface and does not want to be one. A single implementation does not justify
/// an abstraction, and an interface designed against one implementation usually fits the second
/// badly.
/// </para>
/// </remarks>
internal sealed class AuthorizationFlow
{
    private readonly AuthorizationRequestContextTransport _transport;
    private readonly SsoSession _session;
    private readonly PendingPrincipalCookie _pending;
    private readonly TimeProvider _timeProvider;

    public AuthorizationFlow(
        AuthorizationRequestContextTransport transport,
        SsoSession session,
        PendingPrincipalCookie pending,
        TimeProvider timeProvider)
    {
        ArgumentNullException.ThrowIfNull(transport);
        ArgumentNullException.ThrowIfNull(session);
        ArgumentNullException.ThrowIfNull(pending);
        ArgumentNullException.ThrowIfNull(timeProvider);

        _transport = transport;
        _session = session;
        _pending = pending;
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
            ExpiresAt = now + AuthorizationRequestContextTransport.Lifetime,
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

    /// <summary>Reads the interaction context this request is carrying, if any.</summary>
    public AuthorizationRequestContext? Read(HttpContext context) => _transport.TryRead(context);

    /// <summary>
    /// Resolves the interaction this request is entitled to complete: the one the framework sent
    /// the user to a host page for, named by <c>zkd_i</c> and confirmed against the identifier
    /// inside the encrypted context. Never "the current interaction".
    /// </summary>
    /// <exception cref="ZeeKayDaInteractionException">
    /// The request carries no <c>zkd_i</c>, there is no interaction context, or the two do not
    /// name the same interaction.
    /// </exception>
    public async ValueTask<AuthorizationRequestContext> ResolveAddressedAsync(HttpContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        var interactionId = await RequireInteractionIdAsync(context).ConfigureAwait(false);

        var requestContext = Read(context)
            ?? throw new ZeeKayDaInteractionException(
                "There is no active interaction to complete. The authorization request has expired, or " +
                "the login page was reached without going through /connect/authorize.");

        if (!InteractionHandoff.IdentifiersMatch(requestContext.Id, interactionId))
            throw new ZeeKayDaInteractionException(
                "The interaction this request names is not the one this browser is carrying. This is what " +
                "a second sign-in tab looks like: complete the authorization request that was started " +
                "most recently, or start a new one.");

        return requestContext;
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
    /// Persists the context. Returns <see langword="false"/> when the encoded form exceeds what
    /// may safely be carried, in which case nothing is written and the caller must fail the
    /// request.
    /// </summary>
    public bool TryPersist(HttpContext context, AuthorizationRequestContext requestContext) =>
        _transport.TryWrite(context, requestContext);

    /// <summary>
    /// Discards the interaction. Called whenever a request fails, so that a failed or planted
    /// interaction is never left alive for a later sign-in to pick up.
    /// </summary>
    public void Clear(HttpContext context) => _transport.Delete(context);

    /// <summary>Parks a principal an external provider returned, bound to <paramref name="interactionId"/>.</summary>
    public Task ParkPendingAsync(HttpContext context, ClaimsPrincipal principal, string interactionId, string provider) =>
        _pending.WriteAsync(context, principal, interactionId, provider);

    /// <summary>The parked principal bound to <paramref name="interactionId"/>, or <see langword="null"/>.</summary>
    public Task<PendingTicket?> ReadPendingAsync(HttpContext context, string interactionId) =>
        _pending.ReadAsync(context, interactionId);

    /// <summary>
    /// Reads and removes the parked principal. Single-use: whichever sign-in completes the
    /// interaction consumes it, and one bound to another interaction is removed without being
    /// returned.
    /// </summary>
    public Task<PendingTicket?> ConsumePendingAsync(HttpContext context, string interactionId) =>
        _pending.ConsumeAsync(context, interactionId);
}
