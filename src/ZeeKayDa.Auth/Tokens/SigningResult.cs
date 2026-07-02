namespace ZeeKayDa.Auth.Tokens;

/// <summary>
/// The output of a single <see cref="IJwtSigningService.SignAsync"/> call.
/// </summary>
/// <remarks>
/// All segments are already base64url-encoded. The caller assembles the compact JWS by
/// concatenating <c>HeaderSegment + "." + payloadSegment + "." + SignatureSegment</c>.
/// </remarks>
/// <param name="HeaderSegment">
/// The base64url-encoded JWS header, e.g. <c>eyJhbGciOiJSUzI1NiIsImtpZCI6Ii4uLiJ9</c>.
/// </param>
/// <param name="SignatureSegment">
/// The base64url-encoded JWS signature.
/// </param>
/// <param name="Kid">
/// The key identifier used to sign; matches the <c>kid</c> claim in the header.
/// </param>
/// <param name="Algorithm">
/// The algorithm used to sign; matches the <c>alg</c> claim in the header.
/// </param>
public sealed record SigningResult(
    ReadOnlyMemory<byte> HeaderSegment,
    ReadOnlyMemory<byte> SignatureSegment,
    string Kid,
    SigningAlgorithm Algorithm);
