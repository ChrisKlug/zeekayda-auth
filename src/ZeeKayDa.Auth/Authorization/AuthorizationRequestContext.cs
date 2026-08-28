namespace ZeeKayDa.Auth.Authorization;

/// <summary>
/// The state an authorization request needs to survive the redirects between
/// <c>/connect/authorize</c> and the response to the client. Written once when the request
/// validates, then accumulated as the flow advances through authentication and consent.
/// </summary>
/// <remarks>
/// <para>
/// This carries protocol state and a subject <em>reference</em> — never claims, and never a
/// <see cref="System.Security.Claims.ClaimsPrincipal"/>. That rule is what keeps the encoded
/// payload bounded: the authenticated user lives in the session and pending cookies, which are
/// chunked separately. Claims grow without limit; this must not.
/// </para>
/// <para>
/// There is no store behind this. The context is an opaque, encrypted cookie payload — it
/// authenticates nothing on its own, and replay protection belongs to the single-use
/// authorization code.
/// </para>
/// </remarks>
internal sealed record AuthorizationRequestContext
{
    /// <summary>The interaction identifier. The only value that ever leaves the server.</summary>
    public required string Id { get; init; }

    /// <summary>The validated client's identifier.</summary>
    public required string ClientId { get; init; }

    /// <summary>The exact redirect URI the response will be delivered to, authenticated in phase 1.</summary>
    public required string RedirectUri { get; init; }

    /// <summary>The effective scopes: <c>requested ∩ client.AllowedScopes</c>.</summary>
    public required IReadOnlyList<string> Scopes { get; init; }

    /// <summary>The client's opaque <c>state</c>, echoed byte for byte, or <see langword="null"/>.</summary>
    public required string? State { get; init; }

    /// <summary>The OpenID Connect <c>nonce</c>.</summary>
    public required string Nonce { get; init; }

    /// <summary>The PKCE code challenge (RFC 7636 §4.3).</summary>
    public required string CodeChallenge { get; init; }

    /// <summary>The PKCE challenge method.</summary>
    public required CodeChallengeMethod CodeChallengeMethod { get; init; }

    /// <summary>The recognised <c>prompt</c> values.</summary>
    public required IReadOnlySet<PromptValue> Prompts { get; init; }

    /// <summary>The parsed <c>max_age</c>, or <see langword="null"/> when absent.</summary>
    public required TimeSpan? MaxAge { get; init; }

    /// <summary>When the authorization request was accepted.</summary>
    public required DateTimeOffset IssuedAt { get; init; }

    /// <summary>The hard expiry. Not sliding — an interaction gets one window, not a renewable one.</summary>
    public required DateTimeOffset ExpiresAt { get; init; }

    /// <summary>
    /// The SSO session that authenticated the user, or <see langword="null"/> before authentication.
    /// Populated at sign-in promotion and carried through to the authorization code.
    /// </summary>
    public string? SsoSessionId { get; init; }

    /// <summary>
    /// The authenticated subject identifier, or <see langword="null"/> before authentication. A
    /// reference only — no claims about the subject belong here.
    /// </summary>
    public string? Subject { get; init; }

    /// <summary>When the user authenticated, for <c>max_age</c> and the <c>auth_time</c> claim.</summary>
    public DateTimeOffset? AuthTime { get; init; }

    /// <summary>The authentication scheme that authenticated the user.</summary>
    public string? ProviderScheme { get; init; }

    /// <summary>The Authentication Context Class Reference, when one was determined.</summary>
    public string? Acr { get; init; }

    /// <summary>The Authentication Methods References, when they were determined.</summary>
    public IReadOnlyList<string>? Amr { get; init; }

    /// <summary>
    /// The scopes the user consented to, or <see langword="null"/> before a consent decision.
    /// Re-intersected against the client's allowed scopes when the code is issued.
    /// </summary>
    public IReadOnlyList<string>? GrantedScopes { get; init; }

    /// <summary>When the consent decision was recorded.</summary>
    public DateTimeOffset? ConsentedAt { get; init; }
}
