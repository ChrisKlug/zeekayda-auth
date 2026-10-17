namespace ZeeKayDa.Auth.Scopes;

/// <summary>
/// Provides scope definitions used by the authorization server.
/// </summary>
/// <remarks>
/// The framework validates what an implementation returns on every read; a breach of the
/// <see cref="GetScopesAsync"/> contract fails startup and any later request, never worked around.
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
    /// Implementations MUST satisfy all of the following; a breach is reported under the code beside it.
    /// </para>
    /// <list type="bullet">
    /// <item>
    /// The returned collection is never <see langword="null"/> — a repository that knows no scopes
    /// returns an empty collection (<c>scopes.null</c>) — and contains no <see langword="null"/>
    /// element (<c>scopes.element.null</c>).
    /// </item>
    /// <item>
    /// Every <see cref="ScopeDefinition.Name"/> is non-null, non-empty and not whitespace
    /// (<c>scopes.name.blank</c>), is an RFC 6749 §3.3 scope-token — printable ASCII other than
    /// space, <c>"</c> and <c>\</c> (<c>scopes.name.invalid</c>) — and no two definitions share a
    /// name, compared ordinally (<c>scopes.name.duplicate</c>).
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
    /// required to request it (<c>scopes.openid_missing</c>), and its
    /// <see cref="ScopeDefinition.IsDiscoverable"/> is <see langword="true"/>, since OpenID Connect
    /// Discovery 1.0 §3 requires <c>scopes_supported</c> to advertise it (<c>scopes.openid_hidden</c>).
    /// </item>
    /// </list>
    /// <para>
    /// The framework copies each definition before reading it twice, but values must still be stable
    /// for the duration of a call.
    /// </para>
    /// </remarks>
    Task<IReadOnlyCollection<ScopeDefinition>> GetScopesAsync(CancellationToken cancellationToken = default);
}
