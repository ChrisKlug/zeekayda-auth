using System.Buffers;
using System.Buffers.Text;
using System.Security.Cryptography;
using System.Text.Json;

namespace ZeeKayDa.Auth.Tokens;

/// <summary>
/// Computes RFC 7638 JSON Web Key SHA-256 thumbprints, for use as a stable, non-reversible
/// <c>kid</c>.
/// </summary>
/// <remarks>
/// A <c>kid</c> is public, in every token header and the JWKS, so deriving it from a file path, resource
/// URI or row id leaks that identifier. A thumbprint of the public key leaks nothing, stays stable for the
/// key's life, and matches what other JWK tooling computes.
/// </remarks>
public static class JwkThumbprint
{
    // Maps an EC curve OID to the JWK "crv" name RFC 7638's canonical EC member set requires.
    private static readonly IReadOnlyDictionary<string, string> EcCurveOidToJwkCrvName =
        new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["1.2.840.10045.3.1.7"] = "P-256",
            ["1.3.132.0.34"] = "P-384",
            ["1.3.132.0.35"] = "P-521",
        };

    /// <summary>
    /// Computes the RFC 7638 JWK SHA-256 thumbprint of an RSA public key.
    /// </summary>
    /// <param name="rsaPublicParameters">
    /// The RSA public parameters (exponent and modulus only — no private components).
    /// </param>
    /// <returns>The base64url-encoded SHA-256 thumbprint.</returns>
    /// <remarks>
    /// Hashes <c>{"e":…,"kty":"RSA","n":…}</c> with <c>e</c> and <c>n</c> in their minimal big-endian form
    /// (RFC 7518 §6.3.1.1), so a left-padded modulus yields the same <c>kid</c> other tooling derives.
    /// </remarks>
    public static string Compute(RSAParameters rsaPublicParameters)
    {
        var e = Base64Url.EncodeToString(TrimLeadingZeros(rsaPublicParameters.Exponent!));
        var n = Base64Url.EncodeToString(TrimLeadingZeros(rsaPublicParameters.Modulus!));

        return ComputeThumbprint(writer =>
        {
            writer.WriteString("e", e);
            writer.WriteString("kty", "RSA");
            writer.WriteString("n", n);
        });
    }

    /// <summary>
    /// Computes the RFC 7638 JWK SHA-256 thumbprint of an EC public key.
    /// </summary>
    /// <param name="ecPublicParameters">
    /// The EC public parameters (curve and Q point — no private D component). The curve must be
    /// one of NIST P-256, P-384, or P-521.
    /// </param>
    /// <returns>The base64url-encoded SHA-256 thumbprint.</returns>
    /// <exception cref="NotSupportedException">
    /// Thrown when the curve is not one of NIST P-256, P-384, or P-521.
    /// </exception>
    /// <remarks>
    /// Hashes <c>{"crv":…,"kty":"EC","x":…,"y":…}</c>.
    /// </remarks>
    public static string Compute(ECParameters ecPublicParameters)
    {
        var crv = ResolveJwkCurveName(ecPublicParameters.Curve);
        var x = Base64Url.EncodeToString(ecPublicParameters.Q.X!);
        var y = Base64Url.EncodeToString(ecPublicParameters.Q.Y!);

        return ComputeThumbprint(writer =>
        {
            writer.WriteString("crv", crv);
            writer.WriteString("kty", "EC");
            writer.WriteString("x", x);
            writer.WriteString("y", y);
        });
    }

    /// <summary>
    /// Maps <paramref name="curve"/> to its JWK <c>crv</c> name, from the same table the thumbprint uses.
    /// </summary>
    /// <param name="curve">The EC curve. Must be one of NIST P-256, P-384, or P-521.</param>
    /// <returns>The JWK <c>crv</c> name.</returns>
    /// <exception cref="NotSupportedException">
    /// Thrown when the curve is not one of NIST P-256, P-384, or P-521.
    /// </exception>
    internal static string GetJwkCurveName(ECCurve curve) => ResolveJwkCurveName(curve);

    private static string ResolveJwkCurveName(ECCurve curve)
    {
        var curveOid = curve.Oid?.Value;

        if (curveOid is null || !EcCurveOidToJwkCrvName.TryGetValue(curveOid, out var crv))
        {
            throw new NotSupportedException(
                $"EC curve OID '{curveOid ?? "unknown"}' is not supported for JWK thumbprint computation. " +
                "Only NIST P-256, P-384, and P-521 are accepted.");
        }

        return crv;
    }

    /// <summary>Hashes the canonical JWK that <paramref name="writeMembers"/> writes, members in lexicographic order.</summary>
    private static string ComputeThumbprint(Action<Utf8JsonWriter> writeMembers)
    {
        var buffer = new ArrayBufferWriter<byte>();
        using (var writer = new Utf8JsonWriter(buffer, new JsonWriterOptions { Indented = false }))
        {
            writer.WriteStartObject();
            writeMembers(writer);
            writer.WriteEndObject();
        }

        var hash = SHA256.HashData(buffer.WrittenSpan);
        return Base64Url.EncodeToString(hash);
    }

    /// <summary>
    /// Strips leading zero bytes (RFC 7518 §6.3.1.1), keeping one for zero. Shared with the JWK Set writer, so a
    /// served key and its <c>kid</c> cannot use different encodings.
    /// </summary>
    internal static byte[] TrimLeadingZeros(byte[] value)
    {
        var firstNonZero = 0;
        while (firstNonZero < value.Length - 1 && value[firstNonZero] == 0)
            firstNonZero++;

        return firstNonZero == 0 ? value : value[firstNonZero..];
    }
}
