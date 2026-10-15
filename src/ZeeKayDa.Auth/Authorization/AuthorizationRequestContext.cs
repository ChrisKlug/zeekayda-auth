namespace ZeeKayDa.Auth.Authorization;

/// <summary>
/// The state an authorization request carries across the redirects from <c>/connect/authorize</c>
/// to the client's response, accumulated through authentication and consent.
/// </summary>
/// <remarks>
/// Holds a subject reference, never claims, so the payload stays bounded; the user lives in the
/// session cookies. It authenticates nothing: replay protection is the single-use code's.
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

    /// <summary>The OpenID Connect <c>nonce</c>, or <see langword="null"/> when the request carried none.</summary>
    public required string? Nonce { get; init; }

    /// <summary>The PKCE binding (RFC 7636 §4.3), or <see langword="null"/> when the request carried no challenge.</summary>
    public required PkceChallenge? Pkce { get; init; }

    /// <summary>The recognised <c>prompt</c> values.</summary>
    public required IReadOnlySet<PromptValue> Prompts { get; init; }

    /// <summary>The parsed <c>max_age</c>, or <see langword="null"/> when absent.</summary>
    public required TimeSpan? MaxAge { get; init; }

    /// <summary>When the authorization request was accepted.</summary>
    public required DateTimeOffset IssuedAt { get; init; }

    /// <summary>The hard expiry. Not sliding — an interaction gets one window, not a renewable one.</summary>
    public required DateTimeOffset ExpiresAt { get; init; }

    /// <summary>The SSO session that authenticated the user, or <see langword="null"/> before authentication.</summary>
    public string? SsoSessionId { get; init; }

    /// <summary>The authenticated subject identifier, or <see langword="null"/> before authentication.</summary>
    public string? Subject { get; init; }

    /// <summary>The client's unverified <c>login_hint</c> for the login page to pre-fill, or <see langword="null"/>.</summary>
    public string? LoginHint { get; init; }

    /// <summary>When the user authenticated, for <c>max_age</c> and the <c>auth_time</c> claim.</summary>
    public DateTimeOffset? AuthTime { get; init; }

    /// <summary>The authentication scheme that authenticated the user.</summary>
    public string? ProviderScheme { get; init; }

    /// <summary>The Authentication Context Class Reference, when one was determined.</summary>
    public string? Acr { get; init; }

    /// <summary>The Authentication Methods References, when they were determined.</summary>
    public IReadOnlyList<string>? Amr { get; init; }

    /// <summary>The scopes the user consented to, or <see langword="null"/> before a consent decision.</summary>
    public IReadOnlyList<string>? GrantedScopes { get; init; }

    /// <summary>When the consent decision was recorded.</summary>
    public DateTimeOffset? ConsentedAt { get; init; }

    /// <summary>The external provider the user last came back from without signing in, or <see langword="null"/>.</summary>
    public ProviderAttempt? ProviderAttempt { get; init; }
}

/// <summary>An external provider round trip that did not sign the user in, and whether the user declined.</summary>
internal sealed record ProviderAttempt(string Provider, bool Declined);
