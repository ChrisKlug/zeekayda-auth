using System.Text.Json.Serialization;

namespace ZeeKayDa.Auth.Authorization;

/// <summary>
/// OpenID Connect response mode values published in discovery metadata.
/// </summary>
/// <remarks>
/// A mode gets a member only once the authorization endpoint can answer with it, so none is advertised and then refused.
/// </remarks>
[JsonConverter(typeof(JsonStringEnumConverter<ResponseMode>))]
public enum ResponseMode
{
    /// <summary>Query string response mode (<c>query</c>).</summary>
    [JsonStringEnumMemberName("query")]
    Query,
}
