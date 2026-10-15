using ZeeKayDa.Auth.Authorization;

namespace ZeeKayDa.Auth.Stores;

/// <summary>
/// What one authorization code grants, stored between the authorization response and its redemption.
/// Keyed by a hash of the handle and never holding it, so a store breach yields no redeemable code.
/// </summary>
internal sealed record AuthorizationCodeEntry
{
    /// <summary>The client the code was issued to; redemption by another is a <see cref="AuthorizationCodeRedemptionResult.ClientMismatch"/>.</summary>
    public required string ClientId { get; init; }

    /// <summary>The redirect URI the response went to, which redemption must match exactly (RFC 6749 §4.1.3).</summary>
    public required string RedirectUri { get; init; }

    /// <summary>The request's PKCE binding (RFC 7636 §4.3), or <see langword="null"/> for a client allowed to omit it that did.</summary>
    public required PkceChallenge? Pkce { get; init; }

    /// <summary>The authenticated user's <c>sub</c>.</summary>
    public required string Sub { get; init; }

    /// <summary>The granted scopes, which issuance uses rather than the requested ones.</summary>
    public required IReadOnlyList<string> Scope { get; init; }

    /// <summary>The request's <c>nonce</c>, written verbatim into the ID token (OpenID Connect Core 1.0 §3.1.3.7), or <see langword="null"/>.</summary>
    public string? Nonce { get; init; }

    /// <summary>When the user authenticated: the <c>auth_time</c> claim.</summary>
    public required DateTimeOffset AuthTime { get; init; }

    /// <summary>The <c>acr</c> claim, or <see langword="null"/> when none was determined.</summary>
    public string? Acr { get; init; }

    /// <summary>The <c>amr</c> claim, or <see langword="null"/> when none was determined.</summary>
    public IReadOnlyList<string>? Amr { get; init; }

    /// <summary>The SSO session that produced the code.</summary>
    public required string SsoSessionId { get; init; }

    /// <summary>The interaction that produced the code.</summary>
    public required string InteractionId { get; init; }

    /// <summary>When the code was issued.</summary>
    public required DateTimeOffset IssuedAt { get; init; }

    /// <summary>When the code expires; a store treats it as absent afterwards.</summary>
    public required DateTimeOffset ExpiresAt { get; init; }
}
