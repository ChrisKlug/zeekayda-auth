using System.Text.Json.Serialization;

namespace ZeeKayDa.Auth.Authorization;

/// <summary>
/// PKCE code challenge method values that can be advertised in the discovery document, as
/// defined in <see href="https://www.rfc-editor.org/rfc/rfc7636">RFC 7636 (PKCE)</see>.
/// </summary>
/// <remarks>
/// <para>
/// The <c>plain</c> method is intentionally absent.
/// <see href="https://www.rfc-editor.org/rfc/rfc9700#section-2.1.1">RFC 9700 §2.1.1</see>
/// (OAuth 2.0 Security Best Current Practice) explicitly prohibits its use: "The plain code
/// challenge method... MUST NOT be used."
/// </para>
/// <para>
/// New methods are added to this enum only when the framework implements the corresponding
/// verifier at the token endpoint. Do not advertise a method the server cannot verify.
/// </para>
/// </remarks>
[JsonConverter(typeof(JsonStringEnumConverter<CodeChallengeMethod>))]
public enum CodeChallengeMethod
{
    /// <summary>
    /// SHA-256 code challenge method (<c>S256</c>).
    /// Required by
    /// <see href="https://www.rfc-editor.org/rfc/rfc9700#section-2.1.1">RFC 9700 §2.1.1</see>
    /// for all new deployments.
    /// </summary>
    [JsonStringEnumMemberName("S256")]
    S256,
}
