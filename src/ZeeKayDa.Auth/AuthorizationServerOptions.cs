namespace ZeeKayDa.Auth;

/// <summary>
/// Configuration options for the ZeeKayDa authorization server.
/// </summary>
public sealed class AuthorizationServerOptions
{
    /// <summary>
    /// Gets or sets the issuer identifier for this authorization server.
    /// </summary>
    /// <remarks>
    /// Must be an absolute HTTPS URI with no query string or fragment component.
    /// This value is published verbatim as the <c>issuer</c> field in the OIDC Discovery document.
    /// </remarks>
    public string? Issuer { get; set; }

    /// <summary>
    /// Gets or sets a value indicating whether an HTTP (non-HTTPS) issuer URI is permitted.
    /// </summary>
    /// <remarks>
    /// <para>
    /// This is a <strong>development-only</strong> setting. It must never be set to
    /// <see langword="true"/> in production environments. A warning is emitted at startup
    /// whenever this flag is enabled to make the risk visible and intentional.
    /// </para>
    /// <para>
    /// When <see langword="false"/> (the default), an HTTP issuer causes a startup failure via
    /// the fail-fast validator registered by <c>AddZeeKayDaAuth()</c>.
    /// </para>
    /// </remarks>
    public bool AllowInsecureIssuer { get; set; }

    /// <summary>
    /// Gets or sets an explicit override for the <c>authorization_endpoint</c> URI published in
    /// the discovery document. When <see langword="null"/>, the value is derived from
    /// <see cref="Issuer"/>.
    /// </summary>
    public string? AuthorizationEndpoint { get; set; }

    /// <summary>
    /// Gets or sets an explicit override for the <c>token_endpoint</c> URI published in the
    /// discovery document. When <see langword="null"/>, the value is derived from
    /// <see cref="Issuer"/>.
    /// </summary>
    public string? TokenEndpoint { get; set; }

    /// <summary>
    /// Gets or sets an explicit override for the <c>jwks_uri</c> URI published in the discovery
    /// document. When <see langword="null"/>, the value is derived from <see cref="Issuer"/>.
    /// </summary>
    public string? JwksUri { get; set; }

    /// <summary>
    /// Gets or sets the response types supported by this authorization server.
    /// Defaults to <c>[<see cref="ResponseType.Code"/>]</c>.
    /// </summary>
    public ICollection<ResponseType> ResponseTypesSupported { get; set; } = [ResponseType.Code];

    /// <summary>
    /// Gets or sets the response modes supported by this authorization server.
    /// Defaults to <c>[<see cref="ResponseMode.Query"/>]</c>.
    /// </summary>
    public ICollection<ResponseMode> ResponseModesSupported { get; set; } = [ResponseMode.Query];

    /// <summary>
    /// Gets or sets the grant types supported by this authorization server.
    /// Defaults to <c>[<see cref="GrantType.AuthorizationCode"/>]</c>.
    /// </summary>
    public ICollection<GrantType> GrantTypesSupported { get; set; } = [GrantType.AuthorizationCode];

    /// <summary>
    /// Gets or sets the token endpoint client authentication methods supported by this authorization
    /// server. Defaults to <c>[<see cref="TokenEndpointAuthMethod.ClientSecretBasic"/>]</c>.
    /// </summary>
    public ICollection<TokenEndpointAuthMethod> TokenEndpointAuthMethodsSupported { get; set; } =
        [TokenEndpointAuthMethod.ClientSecretBasic];

    /// <summary>
    /// Gets or sets the ID token signing algorithms supported by this authorization server.
    /// Defaults to <c>[<see cref="SigningAlgorithm.RS256"/>]</c>.
    /// </summary>
    public ICollection<SigningAlgorithm> IdTokenSigningAlgValuesSupported { get; set; } = [SigningAlgorithm.RS256];
}
