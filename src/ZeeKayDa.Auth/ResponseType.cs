using System.Text.Json.Serialization;

namespace ZeeKayDa.Auth;

/// <summary>
/// OAuth 2.0 / OpenID Connect response type values, as defined in
/// <see href="https://openid.net/specs/openid-connect-core-1_0.html#Authentication">
/// OpenID Connect Core 1.0</see> and
/// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-3.1.1">RFC 6749 §3.1.1</see>.
/// </summary>
/// <remarks>
/// OAuth 2.1 removes implicit-flow response types (<c>token</c>, <c>id_token</c>,
/// <c>token id_token</c>). Only <see cref="Code"/> is recommended for new deployments.
/// </remarks>
[JsonConverter(typeof(JsonStringEnumConverter<ResponseType>))]
public enum ResponseType
{
    /// <summary>Authorization code flow (<c>code</c>). Recommended by OAuth 2.1.</summary>
    [JsonStringEnumMemberName("code")]
    Code,

    /// <summary>
    /// OpenID Connect hybrid flow returning a code and an ID token
    /// (<c>code id_token</c>).
    /// </summary>
    [JsonStringEnumMemberName("code id_token")]
    CodeIdToken,
}
