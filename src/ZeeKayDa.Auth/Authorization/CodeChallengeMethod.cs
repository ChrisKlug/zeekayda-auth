using System.Text.Json.Serialization;

namespace ZeeKayDa.Auth.Authorization;

/// <summary>
/// PKCE code challenge method values that can be advertised in the discovery document, as
/// defined in <see href="https://www.rfc-editor.org/rfc/rfc7636">RFC 7636 (PKCE)</see>.
/// </summary>
/// <remarks>
/// <c>plain</c> is absent because RFC 9700 §2.1.1 forbids it. A method is added only with its
/// token endpoint verifier, so none is advertised that the server cannot verify.
/// </remarks>
[JsonConverter(typeof(JsonStringEnumConverter<CodeChallengeMethod>))]
public enum CodeChallengeMethod
{
    /// <summary>SHA-256 code challenge method (<c>S256</c>).</summary>
    [JsonStringEnumMemberName("S256")]
    S256,
}
