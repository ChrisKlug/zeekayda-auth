using System.Text.Json.Serialization;

namespace ZeeKayDa.Auth;

/// <summary>
/// JSON Web Signature (JWS) algorithm identifiers used for signing ID tokens and other JWTs,
/// as defined in <see href="https://www.rfc-editor.org/rfc/rfc7518">RFC 7518 (JWA)</see>.
/// </summary>
[JsonConverter(typeof(JsonStringEnumConverter<SigningAlgorithm>))]
public enum SigningAlgorithm
{
    /// <summary>RSASSA-PKCS1-v1_5 using SHA-256.</summary>
    [JsonStringEnumMemberName("RS256")]
    RS256,

    /// <summary>RSASSA-PKCS1-v1_5 using SHA-384.</summary>
    [JsonStringEnumMemberName("RS384")]
    RS384,

    /// <summary>RSASSA-PKCS1-v1_5 using SHA-512.</summary>
    [JsonStringEnumMemberName("RS512")]
    RS512,

    /// <summary>ECDSA using P-256 and SHA-256.</summary>
    [JsonStringEnumMemberName("ES256")]
    ES256,

    /// <summary>ECDSA using P-384 and SHA-384.</summary>
    [JsonStringEnumMemberName("ES384")]
    ES384,

    /// <summary>ECDSA using P-521 and SHA-512.</summary>
    [JsonStringEnumMemberName("ES512")]
    ES512,

    /// <summary>RSASSA-PSS using SHA-256 and MGF1 with SHA-256.</summary>
    [JsonStringEnumMemberName("PS256")]
    PS256,

    /// <summary>RSASSA-PSS using SHA-384 and MGF1 with SHA-384.</summary>
    [JsonStringEnumMemberName("PS384")]
    PS384,

    /// <summary>RSASSA-PSS using SHA-512 and MGF1 with SHA-512.</summary>
    [JsonStringEnumMemberName("PS512")]
    PS512,
}
