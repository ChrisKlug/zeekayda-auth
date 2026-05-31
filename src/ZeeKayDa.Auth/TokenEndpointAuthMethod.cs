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
    [JsonStringEnumMemberName("none")]
    None,
}
