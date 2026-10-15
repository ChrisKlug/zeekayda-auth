using System.Text.Json.Serialization;

namespace ZeeKayDa.Auth;

/// <summary>OAuth 2.0 grant types (RFC 6749 §1.3) that can be advertised in discovery metadata.</summary>
[JsonConverter(typeof(JsonStringEnumConverter<GrantType>))]
public enum GrantType
{
    /// <summary>Authorization code grant (<c>authorization_code</c>).</summary>
    [JsonStringEnumMemberName("authorization_code")]
    AuthorizationCode,

    /// <summary>Refresh token grant (<c>refresh_token</c>).</summary>
    [JsonStringEnumMemberName("refresh_token")]
    RefreshToken,

    /// <summary>Client credentials grant (<c>client_credentials</c>).</summary>
    [JsonStringEnumMemberName("client_credentials")]
    ClientCredentials,
}
