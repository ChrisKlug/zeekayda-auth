using System.Text.Json;

namespace ZeeKayDa.Auth.Tokens;

/// <summary>Reads the claims of a JWT payload: a JSON object (RFC 7519 §7.2).</summary>
internal static class JwtClaims
{
    /// <summary>
    /// <paramref name="payload"/> as a JSON object, which the caller owns and must dispose, or
    /// <see langword="null"/> when it is malformed or not an object.
    /// </summary>
    public static JsonDocument? Parse(ReadOnlyMemory<byte> payload)
    {
        JsonDocument document;
        try
        {
            document = JsonDocument.Parse(payload);
        }
        catch (JsonException ex)
        {
            // Malformed JSON carries no claims, which is all the caller needs to know.
            _ = ex;
            return null;
        }

        if (document.RootElement.ValueKind == JsonValueKind.Object)
            return document;

        document.Dispose();
        return null;
    }

    /// <summary>
    /// The value of <paramref name="name"/> when the payload carries it as a JSON string, or
    /// <see langword="null"/> when it is absent or of any other kind.
    /// </summary>
    public static string? ReadString(JsonElement claims, string name) =>
        claims.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.String
            ? value.GetString()
            : null;
}
