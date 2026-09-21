namespace ZeeKayDa.Auth.Scopes;

/// <summary>
/// Provides scope definitions used by the authorization server.
/// </summary>
/// <remarks>
/// <para>
/// A custom implementation is a caller-supplied extension point whose output the framework
/// validates on every read, the way it validates what a custom <c>IClientRepository</c> serves.
/// An implementation that breaks the contract on <see cref="GetScopesAsync"/> fails startup with a
/// named configuration failure, and fails any later request that reads it — it is never quietly
/// worked around.
/// </para>
/// </remarks>
public interface IScopeRepository
{
    /// <summary>
    /// Returns the scopes known to the authorization server.
    /// </summary>
    /// <param name="cancellationToken">A token that can be used to cancel the operation.</param>
    /// <returns>The configured scope definitions.</returns>
    /// <remarks>
    /// <para>
    /// Implementations MUST satisfy all of the following. Each is checked on every call, and a
    /// breach is reported to the operator under the configuration-failure code named beside it.
    /// </para>
    /// <list type="bullet">
    /// <item>
    /// The returned collection is never <see langword="null"/> — a repository that knows no scopes
    /// returns an empty collection (<c>scopes.null</c>) — and contains no <see langword="null"/>
    /// element (<c>scopes.element.null</c>).
    /// </item>
    /// <item>
    /// Every <see cref="ScopeDefinition.Name"/> is non-null, non-empty and not whitespace
    /// (<c>scopes.name.blank</c>), and no two definitions share a name, compared ordinally
    /// (<c>scopes.name.duplicate</c>).
    /// </item>
    /// <item>
    /// Every claim list — <see cref="ScopeDefinition.IdTokenClaims"/>,
    /// <see cref="ScopeDefinition.UserInfoClaims"/> and
    /// <see cref="ScopeDefinition.AccessTokenClaims"/> — is non-null, and every claim name in it is
    /// non-empty and not whitespace (<c>scopes.claims.blank</c>).
    /// </item>
    /// <item>
    /// No scope lists a protocol claim the framework writes from the grant, <c>sub</c> excepted
    /// (<c>scopes.claims.reserved</c>).
    /// </item>
    /// <item>
    /// Every <see cref="ScopeDefinition.Audience"/> that is set is an absolute URI without a
    /// fragment, as RFC 8707 §2 requires of a resource indicator (<c>scopes.audience.invalid</c>).
    /// </item>
    /// <item>
    /// The <c>openid</c> scope is present, since every OpenID Connect authorization request is
    /// required to request it (<c>scopes.openid_missing</c>).
    /// </item>
    /// </list>
    /// <para>
    /// The framework copies each definition, claim lists included, before it reads one twice, so
    /// mutating a definition after returning it changes nothing the protocol sees. It does not
    /// make the definition safe to mutate: a repository shared across requests must return values
    /// that are stable for the duration of a call.
    /// </para>
    /// </remarks>
    ValueTask<IReadOnlyCollection<ScopeDefinition>> GetScopesAsync(CancellationToken cancellationToken = default);
}
