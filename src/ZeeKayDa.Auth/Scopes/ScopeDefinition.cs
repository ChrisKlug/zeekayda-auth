namespace ZeeKayDa.Auth.Scopes;

/// <summary>
/// Represents a configured scope and the token claim metadata associated with it.
/// </summary>
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
    /// Gets the claim types that should be emitted in the ID token when this scope is granted.
    /// </summary>
    /// <remarks>
    /// This metadata is internal model data for now. It is not published as part of the standard
    /// discovery document, regardless of <see cref="IsDiscoverable"/>.
    /// </remarks>
    public IReadOnlyCollection<string> IdTokenClaims { get; init; } = [];

    /// <summary>
    /// Gets the claim types that should be emitted in the access token when this scope is granted.
    /// </summary>
    /// <remarks>
    /// This metadata is internal model data for now. It is not published as part of the standard
    /// discovery document, regardless of <see cref="IsDiscoverable"/>.
    /// </remarks>
    public IReadOnlyCollection<string> AccessTokenClaims { get; init; } = [];
}
