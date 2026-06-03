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
    /// Represents a public client with no client secret. Authorization-code public clients using
    /// this method must use PKCE (RFC 7636) and present a valid <c>code_verifier</c> at the token
    /// endpoint. See <see cref="AuthorizationServerOptions.GrantTypesSupported"/> and
    /// <see cref="TokenEndpointOptions.AuthMethodsSupported"/> for the server-side configuration
    /// settings that advertise supported grants and token endpoint authentication methods.
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
