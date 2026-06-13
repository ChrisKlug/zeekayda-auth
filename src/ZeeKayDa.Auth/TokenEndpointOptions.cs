namespace ZeeKayDa.Auth;

/// <summary>
/// Token endpoint configuration options.
/// </summary>
public sealed class TokenEndpointOptions
{
    /// <summary>
    /// Gets or sets an explicit override for the <c>token_endpoint</c> URI published in the
    /// discovery document. When <see langword="null"/>, the value is derived from the issuer.
    /// </summary>
    public string? Uri { get; set; }

    /// <summary>
    /// Gets or sets the client authentication methods supported by the token endpoint.
    /// Defaults to <c>[<see cref="TokenEndpointAuthMethod.ClientSecretBasic"/>]</c>.
    /// </summary>
    /// <remarks>
    /// Maps to the <c>token_endpoint_auth_methods_supported</c> discovery metadata field.
    /// Must not be null or empty and must contain at least one non-<see cref="TokenEndpointAuthMethod.None"/>
    /// method if <see cref="AuthorizationServerOptions.GrantTypesSupported"/> includes
    /// <see cref="GrantType.ClientCredentials"/>.
    /// <para>
    /// <see cref="TokenEndpointAuthMethod.ClientSecretPost"/> is opt-in and must be added explicitly.
    /// </para>
    /// </remarks>
    public ICollection<TokenEndpointAuthMethod> AuthMethodsSupported { get; set; } =
        [TokenEndpointAuthMethod.ClientSecretBasic];
}
