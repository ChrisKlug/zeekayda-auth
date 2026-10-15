using System.Buffers;
using System.Text.Json;

namespace ZeeKayDa.Auth.Tokens;

/// <summary>Serialises published signing keys as an RFC 7517 §5 JWK Set.</summary>
/// <remarks>
/// Hand-written so nothing but the intended public members reach the output, in a fixed order, with RSA
/// parameters encoded as <see cref="JwkThumbprint"/> hashes them, so a served key re-derives its <c>kid</c>.
/// </remarks>
internal static class JwkSetWriter
{
    /// <summary>Writes <paramref name="keys"/>, in order, as the UTF-8 bytes of a JWK Set.</summary>
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
