namespace ZeeKayDa.Auth.Tokens;

/// <summary>
/// Issues a token of one <see cref="TokenKind"/> over a finalized set of claims.
/// </summary>
/// <remarks>
/// <para>
/// This is the shape-agnostic seam between deciding a token's contents and producing its wire
/// form. Nothing in the contract is JWS-specific: the shipped <see cref="JwtTokenIssuer"/> signs
/// a JWT via the <see cref="ISigningKeyRing"/>, and a reference-token issuer can return an opaque
/// handle from a store without touching a signing type.
/// </para>
/// <para>
/// The framework resolves the issuer for each token as a keyed DI service, keyed by
/// <see cref="TokenKind"/> — so how access tokens are issued can be swapped without touching how
/// ID tokens are, and vice versa.
/// </para>
/// <para>
/// A host that replaces the ID-token issuer takes over two obligations the framework then no
/// longer performs: writing <c>at_hash</c> over the <see cref="IdTokenIssuanceContext.AccessToken"/>
/// with the hash function the token's own <c>alg</c> implies (OpenID Connect Core §3.1.3.6), and
/// refusing to sign with an algorithm outside the client's
/// <see cref="Clients.IClientMetadata.AllowedSigningAlgorithms"/>. Both belong inside the signing
/// callback, where the key that signs is known; nothing downstream verifies them after the fact.
/// </para>
/// </remarks>
public interface ITokenIssuer
{
    /// <summary>
    /// Issues a token of the requested kind over <paramref name="payload"/>'s claims.
    /// </summary>
    /// <param name="context">
    /// The client the token is for. The concrete type says which token is being issued: an
    /// <see cref="AccessTokenIssuanceContext"/>, or an <see cref="IdTokenIssuanceContext"/> that
    /// also carries the access token the ID token must be bound to.
    /// </param>
    /// <param name="payload">
    /// The finalized claims. The issuer does not select among them and adds only what depends on
    /// the key it resolves — for the framework's JWT issuer, an ID token's <c>at_hash</c> and
    /// nothing else.
    /// </param>
    /// <param name="cancellationToken">A token to cancel the operation.</param>
    /// <returns>The issued token, in the exact form handed to the client.</returns>
    ValueTask<IssuedToken> IssueAsync(
        TokenIssuanceContext context,
        TokenPayload payload,
        CancellationToken cancellationToken = default);
}
