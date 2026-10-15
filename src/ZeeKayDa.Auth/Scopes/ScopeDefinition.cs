namespace ZeeKayDa.Auth.Scopes;

/// <summary>
/// A configured scope: what it unlocks in each destination, and the resource server it is for.
/// </summary>
/// <remarks>
/// <para>
/// Claim types are OpenID Connect wire names (<c>given_name</c>), never <c>ClaimTypes</c> URIs, and every
/// value comes from the host's <c>IClaimsProvider</c>; a type it does not return is omitted.
/// </para>
/// <para>
/// <see cref="StandardScopes"/> lists the §5.4 claims of <c>profile</c>, <c>email</c>, <c>phone</c> and
/// <c>address</c> in <see cref="UserInfoClaims"/> only, where §5.4 places them when an access token is
/// issued. To put them in the ID token too:
/// <c>StandardScopes.Email with { IdTokenClaims = StandardScopes.Email.UserInfoClaims }</c>.
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
    /// A non-discoverable scope still works, but is left out of <c>scopes_supported</c>.
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
    /// Must be an absolute URI without a fragment (RFC 8707 §2), checked on every read. Granted scopes naming
    /// two distinct audiences are refused with <c>invalid_scope</c>: one grant, one API.
    /// </remarks>
    public string? Audience { get; init; }
}
