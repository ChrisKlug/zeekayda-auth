namespace ZeeKayDa.Auth.Tokens;

/// <summary>
/// The kind of token being issued, and the key an <see cref="ITokenIssuer"/> is registered under
/// as a keyed DI service.
/// </summary>
/// <remarks>
/// No refresh token: it is an opaque store handle minted by the grant machinery, never signed.
/// </remarks>
public enum TokenKind
{
    /// <summary>An OAuth 2.0 access token (RFC 6749 §1.4; RFC 9068 when issued as a JWT).</summary>
    AccessToken,

    /// <summary>An OpenID Connect ID token (OpenID Connect Core 1.0 §2).</summary>
    IdToken,
}
