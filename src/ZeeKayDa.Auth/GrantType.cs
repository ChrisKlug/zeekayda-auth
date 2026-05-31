using System.Text.Json.Serialization;

namespace ZeeKayDa.Auth;

/// <summary>
/// OAuth 2.0 grant type values that can be advertised in discovery metadata.
/// </summary>
/// <remarks>
/// Values are based on <see href="https://www.rfc-editor.org/rfc/rfc6749#section-1.3">RFC 6749
/// §1.3</see>.
/// </remarks>
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
