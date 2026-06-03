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
    /// <para>
    /// Represents a public client with no client secret. Public clients cannot securely present
    /// credentials at the token endpoint and must use PKCE (RFC 7636) as the sole protection
    /// mechanism for the authorization code. PKCE is defined only for the authorization code grant,
    /// so <see cref="TokenEndpointAuthMethod.None"/> must be paired with <see cref="GrantType.AuthorizationCode"/>
    /// in <see cref="AuthorizationServerOptions.GrantTypesSupported"/>.
    /// </para>
    /// <para>
    /// See RFC 9700 §2.1.1 (OAuth 2.0 Security Best Current Practice) for the mandatory requirement
    /// that public clients use PKCE, and RFC 7636 (Proof Key for Public OAuth 2.0 Clients) for the
    /// PKCE specification.
    /// </para>
    /// </remarks>
    [JsonStringEnumMemberName("none")]
    None,
}
