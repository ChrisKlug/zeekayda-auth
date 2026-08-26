using System.Buffers;
using System.Text.Json;

namespace ZeeKayDa.Auth.Tokens;

/// <summary>
/// Serialises published signing keys as an RFC 7517 §5 JWK Set document.
/// </summary>
/// <remarks>
/// Hand-rolled over <see cref="Utf8JsonWriter"/> so nothing but the intended public members can
/// reach the output: <c>kid</c>, <c>kty</c>, <c>use</c>, <c>alg</c>, and the public parameters for
/// the key type. The keys appear in the order given, and every member is written in a fixed order,
/// so the same key list always produces byte-identical output. RSA <c>n</c>/<c>e</c> are encoded
/// with the same RFC 7518 §6.3.1.1 minimal encoding <see cref="JwkThumbprint"/> hashes, so a
/// served key's parameters always re-derive its own <c>kid</c>.
/// </remarks>
internal static class JwkSetWriter
{
    /// <summary>
    /// Writes <paramref name="keys"/> as the UTF-8 bytes of a JWK Set document.
    /// </summary>
    /// <param name="keys">The keys to publish, in the order they should appear.</param>
    public static byte[] Write(IReadOnlyList<SigningKey> keys)
    {
        var buffer = new ArrayBufferWriter<byte>();
        using (var writer = new Utf8JsonWriter(buffer, new JsonWriterOptions { Indented = false }))
        {
            writer.WriteStartObject();
            writer.WriteStartArray("keys");

            foreach (var key in keys)
                WriteKey(writer, key);

            writer.WriteEndArray();
            writer.WriteEndObject();
        }

        return buffer.WrittenSpan.ToArray();
    }

    private static void WriteKey(Utf8JsonWriter writer, SigningKey key)
    {
        writer.WriteStartObject();
        writer.WriteString("kid", key.Kid);

        if (key.PublicKey.KeyType == SigningKeyType.Rsa)
        {
            var rsa = key.PublicKey.RsaPublicParameters!.Value;
            writer.WriteString("kty", "RSA");
            WriteCommonMembers(writer, key);
            writer.WriteString("n", JwkThumbprint.Base64UrlEncode(JwkThumbprint.TrimLeadingZeros(rsa.Modulus!)));
            writer.WriteString("e", JwkThumbprint.Base64UrlEncode(JwkThumbprint.TrimLeadingZeros(rsa.Exponent!)));
        }
        else
        {
            var ec = key.PublicKey.EcPublicParameters!.Value;
            writer.WriteString("kty", "EC");
            WriteCommonMembers(writer, key);
            writer.WriteString("crv", JwkThumbprint.GetJwkCurveName(ec.Curve));
            writer.WriteString("x", JwkThumbprint.Base64UrlEncode(ec.Q.X!));
            writer.WriteString("y", JwkThumbprint.Base64UrlEncode(ec.Q.Y!));
        }

        writer.WriteEndObject();
    }

    private static void WriteCommonMembers(Utf8JsonWriter writer, SigningKey key)
    {
        writer.WriteString("use", "sig");
        writer.WriteString("alg", SigningAlgorithms.WireName(key.Algorithm));
    }
}
