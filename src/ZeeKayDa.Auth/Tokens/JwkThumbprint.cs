using System.Buffers;
using System.Buffers.Text;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace ZeeKayDa.Auth.Tokens;

/// <summary>
/// Computes RFC 7638 JSON Web Key SHA-256 thumbprints, for use as a stable, non-reversible
/// <c>kid</c>.
/// </summary>
/// <remarks>
/// This is a public, standalone utility — not tied to any specific <see cref="IJwtSigningService"/>
/// implementation — so that any <c>JwtSigningService&lt;TOptions&gt;</c> author, first-party or
/// third-party, can derive a safe <c>kid</c> without hand-rolling the RFC 7638 canonicalisation
/// themselves. A <c>kid</c> is always public (every issued token header, and the public JWKS), so
/// deriving it from a raw external identifier (a file path, a cloud resource URI, a database row
/// id, …) risks leaking that identifier to anyone who inspects a token or the JWKS. A thumbprint of
/// the public key material itself carries no such information while remaining stable for the life
/// of that key and interoperable with external JWK tooling (jose-jwt, python-jose, online JWK
/// inspectors all compute the same value).
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
    /// The canonical minimal RSA JWK member set, in the lexicographic order RFC 7638 requires, is
    /// <c>{"e":"&lt;b64url(e)&gt;","kty":"RSA","n":"&lt;b64url(n)&gt;"}</c>. <c>e</c> and <c>n</c> are
    /// encoded from their minimal big-endian representation (leading zero bytes stripped) per
    /// RFC 7518 §6.3.1.1, so a modulus left-padded to a fixed byte length still yields the same
    /// <c>kid</c> conformant JWK tooling would derive from it.
    /// </remarks>
    public static string Compute(RSAParameters rsaPublicParameters)
    {
        var e = Base64UrlEncode(TrimLeadingZeros(rsaPublicParameters.Exponent!));
        var n = Base64UrlEncode(TrimLeadingZeros(rsaPublicParameters.Modulus!));

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
    /// The canonical minimal EC JWK member set, in the lexicographic order RFC 7638 requires, is
    /// <c>{"crv":"&lt;name&gt;","kty":"EC","x":"&lt;b64url(x)&gt;","y":"&lt;b64url(y)&gt;"}</c>.
    /// </remarks>
    public static string Compute(ECParameters ecPublicParameters)
    {
        var crv = ResolveJwkCurveName(ecPublicParameters.Curve);
        var x = Base64UrlEncode(ecPublicParameters.Q.X!);
        var y = Base64UrlEncode(ecPublicParameters.Q.Y!);

        return ComputeThumbprint(writer =>
        {
            writer.WriteString("crv", crv);
            writer.WriteString("kty", "EC");
            writer.WriteString("x", x);
            writer.WriteString("y", y);
        });
    }

    /// <summary>
    /// Maps <paramref name="curve"/> to its RFC 7518 §6.2.1.1 JWK <c>crv</c> member name
    /// (<c>"P-256"</c>, <c>"P-384"</c>, or <c>"P-521"</c>).
    /// </summary>
    /// <param name="curve">The EC curve. Must be one of NIST P-256, P-384, or P-521.</param>
    /// <returns>The JWK <c>crv</c> name.</returns>
    /// <exception cref="NotSupportedException">
    /// Thrown when the curve is not one of NIST P-256, P-384, or P-521.
    /// </exception>
    /// <remarks>
    /// Public so that a JWK Set producer (e.g. the JWKS endpoint) does not need to copy this table
    /// across an assembly boundary — this is the same table <see cref="Compute(ECParameters)"/>
    /// uses internally.
    /// </remarks>
    public static string GetJwkCurveName(ECCurve curve) => ResolveJwkCurveName(curve);

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

    /// <summary>
    /// Writes the canonical minimal JWK JSON via <paramref name="writeMembers"/> (which must write
    /// members in lexicographic order) and returns the base64url-encoded SHA-256 hash of the
    /// resulting UTF-8 bytes.
    /// </summary>
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
        return Base64UrlEncode(hash);
    }

    /// <summary>
    /// Strips leading zero bytes from a big-endian unsigned integer, per RFC 7518 §6.3.1.1's minimal
    /// encoding requirement for <c>n</c> and <c>e</c>. A single zero byte is preserved for a
    /// genuinely zero-valued input.
    /// </summary>
    private static byte[] TrimLeadingZeros(byte[] value)
    {
        var firstNonZero = 0;
        while (firstNonZero < value.Length - 1 && value[firstNonZero] == 0)
            firstNonZero++;

        return firstNonZero == 0 ? value : value[firstNonZero..];
    }

    private static string Base64UrlEncode(byte[] input)
    {
        var encoded = new byte[Base64Url.GetEncodedLength(input.Length)];
        Base64Url.EncodeToUtf8(input, encoded);
        return Encoding.ASCII.GetString(encoded);
    }
}
