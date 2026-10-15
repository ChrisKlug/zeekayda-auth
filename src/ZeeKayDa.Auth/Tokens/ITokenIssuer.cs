namespace ZeeKayDa.Auth.Tokens;

/// <summary>
/// Issues a token of one <see cref="TokenKind"/> over a finalized set of claims.
/// </summary>
/// <remarks>
/// <para>
/// Nothing in the contract is JWS-specific: <see cref="JwtTokenIssuer"/> signs a JWT through the
/// <see cref="SigningKeyRing"/>, and a reference-token issuer can return an opaque handle from a store.
/// </para>
/// <para>
/// Resolved as a keyed service per <see cref="TokenKind"/>, so each kind's issuer can be replaced alone.
/// </para>
/// <para>
/// A replacement ID-token issuer takes over two obligations nothing downstream re-checks: writing
/// <c>at_hash</c> over <see cref="IdTokenIssuanceContext.AccessToken"/> with the hash its <c>alg</c>
/// implies (OpenID Connect Core §3.1.3.6), and refusing an algorithm outside the client's
/// <see cref="Clients.IClient.AllowedSigningAlgorithms"/>. Both belong inside the signing callback.
/// </para>
/// </remarks>
public interface ITokenIssuer
{
    /// <summary>
    /// Issues a token of the requested kind over <paramref name="payload"/>'s claims.
    /// </summary>
    /// <param name="context">The client the token is for; the concrete type says which token is issued.</param>
    /// <param name="payload">The finalized claims; the issuer adds only what depends on the key it resolves.</param>
    /// <param name="cancellationToken">A token to cancel the operation.</param>
    /// <returns>The issued token, in the exact form handed to the client.</returns>
    Task<IssuedToken> IssueAsync(
        TokenIssuanceContext context,
        TokenPayload payload,
        CancellationToken cancellationToken = default);
}
