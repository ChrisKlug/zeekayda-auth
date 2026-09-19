using System.Buffers.Text;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace ZeeKayDa.Auth.Tokens;

/// <summary>
/// Reads a compact JWS this server itself signed, and nothing else: a header of the shape the
/// framework's own issuer writes, a key the server still publishes, that key's own algorithm, and
/// a signature that verifies.
/// </summary>
/// <remarks>
/// The one place the framework verifies a token presented back to it, so every such check — the
/// <c>id_token_hint</c> at sign-out, the access token at userinfo — agrees on what "this server
/// signed it" means. It answers only that question: every claim in the payload, expiry included,
/// is the caller's to read and to judge.
/// </remarks>
internal static class SignedTokenReader
{
    /// <summary>The two header members that decide which key verifies, and under which algorithm.</summary>
    private readonly record struct JoseHeader(string Kid, string Algorithm);

    /// <summary>The longest token read at all, in characters. Far above anything this server issues.</summary>
    internal const int MaxLength = 8192;

    /// <summary>
    /// The payload of <paramref name="token"/> when it is a compact JWS this server signed under
    /// one of <paramref name="acceptedTypes"/>, or <see langword="null"/> when it is absent,
    /// unreadable, malformed, or does not verify. Which of those it was is never reported: a
    /// caller able to tell them apart could map the keys and header shapes the server accepts.
    /// </summary>
    /// <param name="token">The token as presented, verbatim.</param>
    /// <param name="acceptedTypes">The <c>typ</c> header values to accept, compared ignoring case.</param>
    /// <param name="published">The keys the server still publishes. Nothing else may verify.</param>
    /// <returns>
    /// The parsed payload object, which the caller owns and must dispose, or <see langword="null"/>.
    /// </returns>
    /// <exception cref="ArgumentNullException">
    /// Thrown when <paramref name="acceptedTypes"/> or <paramref name="published"/> is <see langword="null"/>.
    /// </exception>
    public static JsonDocument? Verify(string? token, string[] acceptedTypes, IReadOnlyList<SigningKey> published)
    {
        ArgumentNullException.ThrowIfNull(acceptedTypes);
        ArgumentNullException.ThrowIfNull(published);

        if (!IsReadable(token))
            return null;

        var segments = token.Split('.');
        if (segments.Length != 3)
            return null;

        try
        {
            var key = ResolveSigningKey(segments[0], acceptedTypes, published);
            if (key is null || !HasValidSignature(key, token, segments[2]))
                return null;

            return ReadPayload(segments[1]);
        }
        catch (Exception ex) when (ex is FormatException or JsonException)
        {
            // Malformed Base64Url or malformed JSON: either means the same as a signature that
            // did not verify.
            _ = ex;
            return null;
        }
    }

    /// <summary>
    /// The value of <paramref name="name"/> when the payload carries it as a JSON string, or
    /// <see langword="null"/> when it is absent or of any other kind.
    /// </summary>
    /// <param name="element">The payload object.</param>
    /// <param name="name">The claim name.</param>
    public static string? ReadString(JsonElement element, string name) =>
        element.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.String
            ? value.GetString()
            : null;

    /// <summary>
    /// The published key the header names, provided the header is one this server writes and
    /// names that key's own algorithm. Nothing is verified against a key the server does not
    /// publish, and the header never chooses how the signature is checked.
    /// </summary>
    private static SigningKey? ResolveSigningKey(
        string headerSegment, string[] acceptedTypes, IReadOnlyList<SigningKey> published)
    {
        if (ReadHeader(headerSegment, acceptedTypes) is not { } header)
            return null;

        var key = published.FirstOrDefault(candidate => string.Equals(candidate.Kid, header.Kid, StringComparison.Ordinal));

        return key is not null && string.Equals(SigningAlgorithms.WireName(key.Algorithm), header.Algorithm, StringComparison.Ordinal)
            ? key
            : null;
    }

    /// <summary>
    /// The <c>kid</c> and <c>alg</c> of a header shaped the way this server's issuer writes one,
    /// or <see langword="null"/> for any other header.
    /// </summary>
    private static JoseHeader? ReadHeader(string headerSegment, string[] acceptedTypes)
    {
        using var header = JsonDocument.Parse(Base64Url.DecodeFromChars(headerSegment));
        var root = header.RootElement;

        // A crit header lists extensions the recipient must understand; this server writes none.
        if (root.ValueKind != JsonValueKind.Object || root.TryGetProperty("crit", out _))
            return null;

        // RFC 7515 §4.1.9: typ carries a media type, whose comparison is case-insensitive.
        if (ReadString(root, "typ") is not { } type || !acceptedTypes.Contains(type, StringComparer.OrdinalIgnoreCase))
            return null;

        return ReadString(root, "kid") is { } kid && ReadString(root, "alg") is { } algorithm
            ? new JoseHeader(kid, algorithm)
            : null;
    }

    /// <summary>
    /// Bytes that are not a signature of the key's algorithm at all, wrong length included, do not
    /// verify; some platforms report that by throwing rather than returning false.
    /// </summary>
    private static bool HasValidSignature(SigningKey key, string token, string signatureSegment)
    {
        var signingInput = Encoding.ASCII.GetBytes(token, 0, token.LastIndexOf('.'));
        var signature = Base64Url.DecodeFromChars(signatureSegment);

        try
        {
            return SigningAlgorithms.Verify(key.Algorithm, key.PublicKey, signingInput, signature);
        }
        catch (Exception ex) when (ex is CryptographicException or ArgumentException or NotSupportedException)
        {
            _ = ex;
            return false;
        }
    }

    /// <summary>A payload that is not a JSON object carries no claims and is refused as unverified.</summary>
    private static JsonDocument? ReadPayload(string payloadSegment)
    {
        var payload = JsonDocument.Parse(Base64Url.DecodeFromChars(payloadSegment));
        if (payload.RootElement.ValueKind == JsonValueKind.Object)
            return payload;

        payload.Dispose();
        return null;
    }

    /// <summary>
    /// Whether the token is worth reading at all. Only ASCII is accepted because every segment of
    /// a compact JWS is Base64Url, and the signing input is taken as the token's ASCII bytes.
    /// </summary>
    private static bool IsReadable([NotNullWhen(true)] string? token) =>
        !string.IsNullOrEmpty(token) && token.Length <= MaxLength && Ascii.IsValid(token);
}
