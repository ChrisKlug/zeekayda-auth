namespace ZeeKayDa.Auth.Tokens;

/// <summary>
/// The kind of token being issued, and the key an <see cref="ITokenIssuer"/> is registered under
/// as a keyed DI service.
/// </summary>
/// <remarks>
/// Refresh tokens are deliberately absent: they are opaque store handles minted by the grant
/// machinery, not issued through a signing path. Routing them through <see cref="ITokenIssuer"/>
/// would pre-empt the reference-token design (#284). Adding a member later is additive.
/// </remarks>
public enum TokenKind
{
    /// <summary>An OAuth 2.0 access token (RFC 6749 §1.4; RFC 9068 when issued as a JWT).</summary>
    AccessToken,

    /// <summary>An OpenID Connect ID token (OpenID Connect Core 1.0 §2).</summary>
    IdToken,
}
