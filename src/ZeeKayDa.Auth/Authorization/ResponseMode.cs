using System.Text.Json.Serialization;

namespace ZeeKayDa.Auth.Authorization;

/// <summary>
/// OpenID Connect response mode values published in discovery metadata.
/// </summary>
/// <remarks>
/// See <see href="https://openid.net/specs/oauth-v2-multiple-response-types-1_0.html">OAuth 2.0
/// Multiple Response Type Encoding Practices</see> and
/// <see href="https://openid.net/specs/oauth-v2-form-post-response-mode-1_0.html">OAuth 2.0
/// Form Post Response Mode</see>.
/// </remarks>
[JsonConverter(typeof(JsonStringEnumConverter<ResponseMode>))]
public enum ResponseMode
{
    /// <summary>Query string response mode (<c>query</c>).</summary>
    [JsonStringEnumMemberName("query")]
    Query,

    /// <summary>Form post response mode (<c>form_post</c>).</summary>
    [JsonStringEnumMemberName("form_post")]
    FormPost,
}
