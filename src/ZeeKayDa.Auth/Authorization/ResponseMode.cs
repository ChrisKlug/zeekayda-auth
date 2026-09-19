using System.Text.Json.Serialization;

namespace ZeeKayDa.Auth.Authorization;

/// <summary>
/// OpenID Connect response mode values published in discovery metadata.
/// </summary>
/// <remarks>
/// See <see href="https://openid.net/specs/oauth-v2-multiple-response-types-1_0.html">OAuth 2.0
/// Multiple Response Type Encoding Practices</see>. A mode gets a member only once the authorization
/// endpoint can answer with it, so there is no <c>form_post</c> yet: a member with nothing behind it
/// could be configured and advertised, and every request asking for it refused.
/// </remarks>
[JsonConverter(typeof(JsonStringEnumConverter<ResponseMode>))]
public enum ResponseMode
{
    /// <summary>Query string response mode (<c>query</c>).</summary>
    [JsonStringEnumMemberName("query")]
    Query,
}
