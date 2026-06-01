using System.Text.Json.Serialization;

namespace ZeeKayDa.Auth;

/// <summary>
/// Client authentication methods that can be advertised for the token endpoint.
/// </summary>
/// <remarks>
/// Values are based on OpenID Connect Discovery 1.0 §3 and the corresponding client
/// authentication methods defined by OAuth 2.0 and OpenID Connect.
/// </remarks>
[JsonConverter(typeof(JsonStringEnumConverter<TokenEndpointAuthMethod>))]
public enum TokenEndpointAuthMethod
{
    /// <summary>HTTP Basic authentication with client secret (<c>client_secret_basic</c>).</summary>
    [JsonStringEnumMemberName("client_secret_basic")]
    ClientSecretBasic,

    /// <summary>Client secret sent in the request body (<c>client_secret_post</c>).</summary>
    [JsonStringEnumMemberName("client_secret_post")]
    ClientSecretPost,

    /// <summary>JWT assertion signed with a shared secret (<c>client_secret_jwt</c>).</summary>
    [JsonStringEnumMemberName("client_secret_jwt")]
    ClientSecretJwt,

    /// <summary>JWT assertion signed with the client's private key (<c>private_key_jwt</c>).</summary>
    [JsonStringEnumMemberName("private_key_jwt")]
    PrivateKeyJwt,

    /// <summary>No client authentication (<c>none</c>).</summary>
    /// <remarks>
    /// Clients using this authentication method are public clients (e.g., single-page applications,
    /// mobile apps) that cannot keep a secret. Because there is no client credential to verify at the
    /// token endpoint, the only binding between the authorization request and the token exchange is the
    /// PKCE <c>code_verifier</c>. Clients using <c>none</c> <b>MUST</b> present a valid PKCE
    /// <c>code_verifier</c> at the token endpoint.
    /// <para>
    /// Per <see href="https://www.rfc-editor.org/rfc/rfc9700#section-2.4">RFC 9700 §2.4</see> and
    /// OAuth 2.1 §4.1.1, public clients MUST use PKCE. The PKCE specification is defined in
    /// <see href="https://www.rfc-editor.org/rfc/rfc7636">RFC 7636</see>.
    /// </para>
    /// </remarks>
    [JsonStringEnumMemberName("none")]
    None,
}
