using System.Security.Claims;
using Microsoft.AspNetCore.Http;
using ZeeKayDa.Auth.Authorization;

namespace ZeeKayDa.Auth.AspNetCore.Interaction;

/// <summary>
/// The interaction state of an authorization request, and the single seam through which every
/// stage of the flow reads and writes it: the authorization endpoint, the login page's
/// interaction service, and — when they land — consent and code issuance.
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
    private readonly TimeProvider _timeProvider;

    public AuthorizationFlow(
        AuthorizationRequestContextTransport transport,
        SsoSession session,
        TimeProvider timeProvider)
    {
        ArgumentNullException.ThrowIfNull(transport);
        ArgumentNullException.ThrowIfNull(session);
        ArgumentNullException.ThrowIfNull(timeProvider);

        _transport = transport;
        _session = session;
        _timeProvider = timeProvider;
    }

    /// <summary>Reads the established SSO session, or <see langword="null"/> when there is none.</summary>
    public Task<SsoSessionState?> ReadSessionAsync(HttpContext context) => _session.ReadAsync(context);

    /// <summary>Establishes the SSO session for an authenticated principal.</summary>
    public Task<SsoSessionState> PromoteAsync(HttpContext context, ClaimsPrincipal principal, string amr) =>
        _session.PromoteAsync(context, principal, amr);

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

    /// <summary>Reads the interaction context this request is carrying, if any.</summary>
    public AuthorizationRequestContext? Read(HttpContext context) => _transport.TryRead(context);

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
}
