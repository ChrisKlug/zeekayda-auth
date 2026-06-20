using ZeeKayDa.Auth.Authorization;

namespace ZeeKayDa.Auth.Stores;

/// <summary>
/// Represents all claims and metadata associated with a single authorization code that the store
/// must persist between the authorization endpoint response and the token endpoint redemption.
/// </summary>
/// <remarks>
/// <para>
/// The raw code handle is intentionally absent from this record. Replay detection is performed
/// via a SHA-256 hash of the handle, which is used as the cache/store key. The entry itself
/// never contains the cleartext code, so a store breach cannot yield redeemable handles.
/// </para>
/// <para>
/// All properties marked <see langword="required"/> must be set at construction time via object
/// initialiser syntax (or a positional constructor if the record is extended). Nullable properties
/// are optional and may be omitted for pure OAuth 2.0 flows that do not use the corresponding
/// feature.
/// </para>
/// <para>
/// Authorization codes are short-lived. The framework enforces a configurable maximum lifetime
/// (default: 60 seconds per RFC 6749 §4.1.2 guidance). Implementations should honour
/// <see cref="ExpiresAt"/> and refuse to return an entry past its expiry.
/// </para>
/// </remarks>
public sealed record AuthorizationCodeEntry
{
    /// <summary>
    /// The client identifier to which this code was issued (RFC 6749 §4.1.2).
    /// </summary>
    /// <remarks>
    /// The token endpoint MUST verify that the presenting <c>client_id</c> matches this value
    /// before accepting the code. A mismatch MUST be surfaced as
    /// <see cref="AuthorizationCodeRedemptionOutcome.ClientMismatch"/>.
    /// </remarks>
    public required string ClientId { get; init; }

    /// <summary>
    /// The redirect URI to which the authorization response was delivered (RFC 6749 §4.1.3).
    /// </summary>
    /// <remarks>
    /// The token endpoint MUST perform an exact byte-for-byte comparison of the
    /// <c>redirect_uri</c> parameter against this value and reject the request if they differ.
    /// </remarks>
    public required string RedirectUri { get; init; }

    /// <summary>
    /// The PKCE code challenge value as submitted by the client in the authorization request
    /// (RFC 7636 §4.3).
    /// </summary>
    /// <remarks>
    /// Stored as-is (Base64url-encoded SHA-256 digest of the verifier). The token endpoint
    /// recomputes SHA-256(verifier) and compares it against this value.
    /// </remarks>
    public required string CodeChallenge { get; init; }

    /// <summary>
    /// The PKCE code challenge method. Always <see cref="CodeChallengeMethod.S256"/> in the
    /// current implementation; stored to allow future method negotiation without schema changes.
    /// </summary>
    public required CodeChallengeMethod CodeChallengeMethod { get; init; }

    /// <summary>
    /// The subject identifier (<c>sub</c>) of the authenticated end-user.
    /// </summary>
    public required string Sub { get; init; }

    /// <summary>
    /// The space-separated list of scopes granted to the client for this authorization.
    /// </summary>
    /// <remarks>
    /// The granted scope may be equal to or narrower than the requested scope. The token endpoint
    /// MUST use this value — not the original request — when issuing access and refresh tokens.
    /// </remarks>
    public required string Scope { get; init; }

    /// <summary>
    /// The OpenID Connect nonce value carried forward from the authorization request, or
    /// <see langword="null"/> for pure OAuth 2.0 flows that did not include a nonce.
    /// </summary>
    /// <remarks>
    /// When non-null, this value MUST be included verbatim in the <c>nonce</c> claim of the
    /// ID token issued at the token endpoint (OpenID Connect Core 1.0 §3.1.3.7).
    /// </remarks>
    public string? Nonce { get; init; }

    /// <summary>
    /// The UTC timestamp at which the end-user was authenticated.
    /// </summary>
    /// <remarks>
    /// Used to populate the <c>auth_time</c> claim in the ID token
    /// (OpenID Connect Core 1.0 §2).
    /// </remarks>
    public required DateTimeOffset AuthTime { get; init; }

    /// <summary>
    /// The Authentication Context Class Reference (<c>acr</c>) value, or
    /// <see langword="null"/> if not determined during authentication.
    /// </summary>
    /// <remarks>
    /// When non-null, included in the <c>acr</c> claim of the ID token
    /// (OpenID Connect Core 1.0 §2).
    /// </remarks>
    public string? Acr { get; init; }

    /// <summary>
    /// The Authentication Methods References (<c>amr</c>) list, or <see langword="null"/> if
    /// not determined during authentication.
    /// </summary>
    /// <remarks>
    /// When non-null, included as the <c>amr</c> claim (an array) in the ID token
    /// (OpenID Connect Core 1.0 §2).
    /// </remarks>
    public IReadOnlyList<string>? Amr { get; init; }

    /// <summary>
    /// The SSO session identifier that produced this authorization code. Binds the code to
    /// the user's active session so that the session can be referenced or invalidated at
    /// token endpoint time.
    /// </summary>
    public required string SsoSessionId { get; init; }

    /// <summary>
    /// The interaction context identifier that produced this authorization code. Correlates
    /// the token-endpoint redemption back to the original authorization interaction for
    /// auditing and consent tracking.
    /// </summary>
    public required string InteractionId { get; init; }

    /// <summary>
    /// The UTC timestamp at which this authorization code was issued.
    /// </summary>
    public required DateTimeOffset IssuedAt { get; init; }

    /// <summary>
    /// The UTC timestamp at which this authorization code expires.
    /// </summary>
    /// <remarks>
    /// Store implementations MUST treat entries past this timestamp as non-existent, returning
    /// <see cref="AuthorizationCodeRedemptionOutcome.NotFound"/> rather than exposing expired
    /// entries to callers.
    /// </remarks>
    public required DateTimeOffset ExpiresAt { get; init; }
}
