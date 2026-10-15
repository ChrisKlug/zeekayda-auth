using System.Text.Json.Serialization;
using ZeeKayDa.Auth;
using ZeeKayDa.Auth.Authorization;
using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.Discovery;

/// <summary>
/// The OpenID Connect Discovery 1.0 §3 provider metadata document, kept apart from
/// <see cref="AuthorizationServerOptions"/> so configuration and wire format evolve independently.
/// </summary>
internal sealed record OpenIdConfigurationDocument
{
    /// <summary>Gets the issuer identifier of the authorization server.</summary>
    [JsonPropertyName("issuer")]
    public required string Issuer { get; init; }

    /// <summary>
    /// Gets the URL of the authorization endpoint, or <see langword="null"/> and absent when no
    /// supported grant uses it (RFC 8414 §2).
    /// </summary>
    [JsonPropertyName("authorization_endpoint")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? AuthorizationEndpoint { get; init; }

    /// <summary>Gets the URL of the token endpoint.</summary>
    [JsonPropertyName("token_endpoint")]
    public required string TokenEndpoint { get; init; }

    /// <summary>Gets the URL of the JSON Web Key Set document.</summary>
    [JsonPropertyName("jwks_uri")]
    public required string JwksUri { get; init; }

    /// <summary>
    /// Gets the URL of the UserInfo endpoint (OpenID Connect Core §5.3), served only alongside the
    /// authorization endpoint; absent when <see langword="null"/>.
    /// </summary>
    [JsonPropertyName("userinfo_endpoint")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? UserInfoEndpoint { get; init; }

    /// <summary>
    /// Gets the URL of the end-session endpoint (RP-Initiated Logout 1.0 §2.1), served only
    /// alongside the authorization endpoint; absent when <see langword="null"/>.
    /// </summary>
    [JsonPropertyName("end_session_endpoint")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? EndSessionEndpoint { get; init; }

    /// <summary>
    /// Gets the supported response types, or <see langword="null"/> and absent without an
    /// authorization endpoint, since Discovery §4.2 omits a zero-element claim.
    /// </summary>
    [JsonPropertyName("response_types_supported")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public IReadOnlyCollection<ResponseType>? ResponseTypesSupported { get; init; }

    /// <summary>Gets the scopes supported by this authorization server.</summary>
    [JsonPropertyName("scopes_supported")]
    public required IReadOnlyCollection<string> ScopesSupported { get; init; }

    /// <summary>
    /// Gets the claims the server may supply in an ID token or at UserInfo (Discovery §3); absent
    /// on the same condition as <see cref="ResponseTypesSupported"/>.
    /// </summary>
    [JsonPropertyName("claims_supported")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public IReadOnlyCollection<string>? ClaimsSupported { get; init; }

    /// <summary>
    /// Gets the supported response modes; absent on the same condition as <see cref="ResponseTypesSupported"/>.
    /// </summary>
    [JsonPropertyName("response_modes_supported")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public IReadOnlyCollection<ResponseMode>? ResponseModesSupported { get; init; }

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

    /// <summary>Gets the JWS signing algorithms supported for ID tokens.</summary>
    [JsonPropertyName("id_token_signing_alg_values_supported")]
    public required IReadOnlyCollection<SigningAlgorithm> IdTokenSigningAlgValuesSupported { get; init; }

    /// <summary>
    /// Whether the authorization response carries <c>iss</c> (RFC 9207 §3); absent when <see langword="null"/>.
    /// </summary>
    /// <remarks>Published, since a client assumes <see langword="false"/> when it is omitted and may skip the check.</remarks>
    [JsonPropertyName("authorization_response_iss_parameter_supported")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public bool? AuthorizationResponseIssParameterSupported { get; init; }

    /// <summary>Gets the supported PKCE code challenge methods; absent when <see langword="null"/>.</summary>
    [JsonPropertyName("code_challenge_methods_supported")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public IReadOnlyCollection<CodeChallengeMethod>? CodeChallengeMethodsSupported { get; init; }
}
