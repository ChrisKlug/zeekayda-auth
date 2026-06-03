namespace ZeeKayDa.Auth;

/// <summary>
/// Authorization endpoint configuration options.
/// </summary>
public sealed class AuthorizationEndpointOptions
{
    /// <summary>
    /// Gets or sets an explicit override for the <c>authorization_endpoint</c> URI published in
    /// the discovery document. When <see langword="null"/>, the value is derived from the issuer.
    /// </summary>
    public string? Uri { get; set; }

    /// <summary>
    /// Gets or sets the PKCE code challenge methods supported by this authorization server.
    /// When <see langword="null"/> (the default), the <c>code_challenge_methods_supported</c>
    /// field is omitted from the discovery document.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Set to <c>[<see cref="CodeChallengeMethod.S256"/>]</c> once PKCE challenge verification
    /// is enforced at the token endpoint. Advertising methods the server does not actually verify
    /// gives clients a false assurance — do not set this property until enforcement is in place.
    /// </para>
    /// <para>
    /// Maps to the <c>code_challenge_methods_supported</c> discovery metadata field defined in
    /// <see href="https://www.rfc-editor.org/rfc/rfc7636#section-4.3">RFC 7636 §4.3</see> and
    /// <see href="https://www.rfc-editor.org/rfc/rfc8414#section-2">RFC 8414 §2</see>.
    /// </para>
    /// </remarks>
    public ICollection<CodeChallengeMethod>? CodeChallengeMethodsSupported { get; set; }
}
