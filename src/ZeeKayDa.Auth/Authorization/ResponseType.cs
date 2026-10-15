using System.Text.Json.Serialization;

namespace ZeeKayDa.Auth.Authorization;

/// <summary>
/// OAuth 2.0 / OpenID Connect response type values, as defined in
/// <see href="https://openid.net/specs/openid-connect-core-1_0.html#Authentication">
/// OpenID Connect Core 1.0</see> and
/// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-3.1.1">RFC 6749 §3.1.1</see>.
/// </summary>
/// <remarks>Only the authorization code response type; hybrid and implicit are not offered.</remarks>
[JsonConverter(typeof(JsonStringEnumConverter<ResponseType>))]
public enum ResponseType
{
    /// <summary>Authorization code flow (<c>code</c>). Recommended by OAuth 2.1.</summary>
    [JsonStringEnumMemberName("code")]
    Code,
}
