using System.Text.Json.Serialization;

namespace ZeeKayDa.Auth.Discovery;

/// <summary>
/// Represents an OpenID Connect Discovery 1.0 provider metadata document as specified in §3 of
/// the OpenID Connect Discovery specification.
/// </summary>
/// <remarks>
/// This record is the stable wire-format contract for the discovery endpoint. It is intentionally
/// separate from <see cref="AuthorizationServerOptions"/> so that the configuration model and the
/// published JSON can evolve independently.
/// </remarks>
public sealed record OpenIdConfigurationDocument
{
    /// <summary>Gets the issuer identifier of the authorization server.</summary>
    [JsonPropertyName("issuer")]
    public required string Issuer { get; init; }

    /// <summary>Gets the URL of the authorization endpoint.</summary>
    [JsonPropertyName("authorization_endpoint")]
    public required string AuthorizationEndpoint { get; init; }

    /// <summary>Gets the URL of the token endpoint.</summary>
    [JsonPropertyName("token_endpoint")]
    public required string TokenEndpoint { get; init; }

    /// <summary>Gets the URL of the JSON Web Key Set document.</summary>
    [JsonPropertyName("jwks_uri")]
    public required string JwksUri { get; init; }

    /// <summary>Gets the OAuth 2.0 response types supported by this authorization server.</summary>
    [JsonPropertyName("response_types_supported")]
    public required IReadOnlyCollection<ResponseType> ResponseTypesSupported { get; init; }

    /// <summary>Gets the scopes supported by this authorization server.</summary>
    [JsonPropertyName("scopes_supported")]
    public required IReadOnlyCollection<string> ScopesSupported { get; init; }

    /// <summary>Gets the response modes supported by this authorization server.</summary>
    [JsonPropertyName("response_modes_supported")]
    public required IReadOnlyCollection<ResponseMode> ResponseModesSupported { get; init; }

    /// <summary>Gets the grant types supported by this authorization server.</summary>
    [JsonPropertyName("grant_types_supported")]
    public required IReadOnlyCollection<GrantType> GrantTypesSupported { get; init; }

    /// <summary>Gets the token endpoint authentication methods supported by this authorization server.</summary>
    [JsonPropertyName("token_endpoint_auth_methods_supported")]
    public required IReadOnlyCollection<string> TokenEndpointAuthMethodsSupported { get; init; }

    /// <summary>Gets the subject identifier types supported by this authorization server.</summary>
    /// <remarks>Always <c>["public"]</c>. Pairwise subject identifiers are not supported.</remarks>
    [JsonPropertyName("subject_types_supported")]
    public IReadOnlyCollection<string> SubjectTypesSupported { get; } = ["public"];

    /// <summary>
    /// Gets the JWS signing algorithms supported for ID tokens issued by this authorization server.
    /// </summary>
    [JsonPropertyName("id_token_signing_alg_values_supported")]
    public required IReadOnlyCollection<SigningAlgorithm> IdTokenSigningAlgValuesSupported { get; init; }

    /// <summary>
    /// Gets the PKCE code challenge methods supported by this authorization server.
    /// Absent from the document when <see langword="null"/>.
    /// </summary>
    [JsonPropertyName("code_challenge_methods_supported")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public IReadOnlyCollection<CodeChallengeMethod>? CodeChallengeMethodsSupported { get; init; }
}
