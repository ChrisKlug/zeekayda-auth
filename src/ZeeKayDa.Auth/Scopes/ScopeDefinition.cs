namespace ZeeKayDa.Auth.Scopes;

/// <summary>
/// A configured scope: what it unlocks in each destination, and the resource server it is for.
/// </summary>
/// <remarks>
/// <para>
/// A scope names the claim types it unlocks in the ID token, at the userinfo endpoint, and in the
/// access token. Claim type names are OpenID Connect wire names (<c>given_name</c>, <c>email</c>),
/// never <c>ClaimTypes</c> URIs, and every value comes from the host's <c>IClaimsProvider</c>: a
/// listed type the provider does not return is omitted, never written empty.
/// </para>
/// <para>
/// <see cref="StandardScopes"/> lists the OpenID Connect Core §5.4 claims of each standard scope
/// in <see cref="UserInfoClaims"/> only, which is where §5.4 places them when an access token is
/// issued, as it always is in the code flow. A host that wants them in the ID token as well adds
/// them: <c>StandardScopes.Email with { IdTokenClaims = StandardScopes.Email.UserInfoClaims }</c>.
/// </para>
/// </remarks>
public sealed record ScopeDefinition
{
    /// <summary>
    /// Gets the scope name, for example <c>openid</c> or <c>profile</c>.
    /// </summary>
    public required string Name { get; init; }

    /// <summary>
    /// Gets whether this scope should be published in discovery metadata.
    /// </summary>
    /// <remarks>
    /// Defaults to <see langword="true"/>. Non-discoverable scopes may still exist in the
    /// repository for internal or client-specific use, but they are excluded from
    /// <c>scopes_supported</c>.
    /// </remarks>
    public bool IsDiscoverable { get; init; } = true;

    /// <summary>
    /// Gets the claim types emitted in the ID token when this scope is granted.
    /// </summary>
    public IReadOnlyCollection<string> IdTokenClaims { get; init; } = [];

    /// <summary>
    /// Gets the claim types returned from the userinfo endpoint when this scope is granted.
    /// </summary>
    public IReadOnlyCollection<string> UserInfoClaims { get; init; } = [];

    /// <summary>
    /// Gets the claim types emitted in the access token when this scope is granted.
    /// </summary>
    public IReadOnlyCollection<string> AccessTokenClaims { get; init; } = [];

    /// <summary>
    /// Gets the resource server this scope is for, as the absolute URI that becomes the access
    /// token's <c>aud</c> when the scope is granted (RFC 9068 §3), or <see langword="null"/> for
    /// an identity scope, whose audience is the issuer.
    /// </summary>
    /// <remarks>
    /// Must be an absolute URI without a fragment (RFC 8707 §2), checked at startup. Two scopes
    /// with the same value are the same API. A request whose granted scopes name two distinct
    /// values is refused with <c>invalid_scope</c>: one grant, one API.
    /// </remarks>
    public string? Audience { get; init; }
}
