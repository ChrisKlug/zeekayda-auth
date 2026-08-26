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
/// </remarks>
public interface ITokenIssuer
{
    /// <summary>
    /// Issues a token of the requested kind over <paramref name="payload"/>'s claims.
    /// </summary>
    /// <param name="context">The client the token is for, and the kind being issued.</param>
    /// <param name="payload">The finalized claims. The issuer does not select or amend them.</param>
    /// <param name="cancellationToken">A token to cancel the operation.</param>
    /// <returns>The issued token, in the exact form handed to the client.</returns>
    ValueTask<IssuedToken> IssueAsync(
        TokenIssuanceContext context,
        TokenPayload payload,
        CancellationToken cancellationToken = default);
}
