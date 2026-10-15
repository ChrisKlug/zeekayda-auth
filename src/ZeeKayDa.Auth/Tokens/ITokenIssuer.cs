namespace ZeeKayDa.Auth.Tokens;

/// <summary>
/// Issues a token of one <see cref="TokenKind"/> over a finalized set of claims.
/// </summary>
/// <remarks>
/// Resolved as a keyed service per <see cref="TokenKind"/>. Internal: userinfo accepts only JWTs this
/// server signed and there is no introspection, so no replacement could work. A reference-token seam
/// is designed with refresh tokens.
/// </remarks>
internal interface ITokenIssuer
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
