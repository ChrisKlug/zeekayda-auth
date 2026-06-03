using System.Text.Json.Serialization;

namespace ZeeKayDa.Auth;

/// <summary>
/// OAuth 2.0 / OpenID Connect response type values, as defined in
/// <see href="https://openid.net/specs/openid-connect-core-1_0.html#Authentication">
/// OpenID Connect Core 1.0</see> and
/// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-3.1.1">RFC 6749 §3.1.1</see>.
/// </summary>
/// <remarks>
/// ZeeKayDa.Auth supports the authorization code response type only.
/// Hybrid and implicit response types are intentionally not exposed.
/// </remarks>
[JsonConverter(typeof(JsonStringEnumConverter<ResponseType>))]
public enum ResponseType
{
    /// <summary>Authorization code flow (<c>code</c>). Recommended by OAuth 2.1.</summary>
    [JsonStringEnumMemberName("code")]
    Code,
}
