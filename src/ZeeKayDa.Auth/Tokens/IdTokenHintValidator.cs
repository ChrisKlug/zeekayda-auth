using System.Buffers.Text;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Options;

namespace ZeeKayDa.Auth.Tokens;

/// <summary>
/// The client and user named by an <c>id_token_hint</c> that has been proven to be one of this
/// server's own ID tokens.
/// </summary>
/// <param name="ClientId">The client the ID token was issued to: its <c>aud</c>.</param>
/// <param name="Subject">The user the ID token was issued for: its <c>sub</c>.</param>
internal sealed record IdTokenHint(string ClientId, string Subject);

/// <summary>
/// Decides whether an <c>id_token_hint</c> is an ID token this server issued, and if so, which
/// client and user it names.
/// </summary>
/// <remarks>
/// Accepts exactly what the framework's own issuer writes and nothing else: a compact JWS with
/// <c>typ</c> <c>JWT</c>, signed by a key the server still publishes, under that key's own
/// algorithm, carrying this server's <c>iss</c>, a <c>sub</c>, and a single-string <c>aud</c>. The
/// token's lifetime is not checked: a relying party sends the ID token it received at sign-in,
/// which has usually expired by the time the user signs out, and the hint only has to prove where
/// it came from.
/// </remarks>
internal sealed class IdTokenHintValidator
{
    /// <summary>The longest hint read at all, in characters. Far above any ID token this server issues.</summary>
    internal const int MaxLength = 8192;

    private const string IdTokenType = "JWT";

    private readonly ISigningKeyRing _keyRing;
    private readonly IOptions<AuthorizationServerOptions> _options;

    public IdTokenHintValidator(ISigningKeyRing keyRing, IOptions<AuthorizationServerOptions> options)
    {
        ArgumentNullException.ThrowIfNull(keyRing);
        ArgumentNullException.ThrowIfNull(options);

        _keyRing = keyRing;
        _options = options;
    }

    /// <summary>
    /// Returns the client and user <paramref name="idTokenHint"/> names, or <see langword="null"/>
    /// when it is absent or is not an ID token this server issued, in which case the caller proceeds
    /// as if no hint was sent. Why a hint was refused is never reported.
    /// </summary>
    /// <param name="idTokenHint">The <c>id_token_hint</c> request parameter, verbatim.</param>
    /// <param name="clientId">
    /// The <c>client_id</c> request parameter, when the request carried one. A hint issued to any
    /// other client is refused.
    /// </param>
    /// <exception cref="InvalidOperationException">
    /// The signing key ring has not completed startup initialization.
    /// </exception>
    public IdTokenHint? Validate(string? idTokenHint, string? clientId)
    {
        if (!IsReadable(idTokenHint))
            return null;

        var segments = idTokenHint.Split('.');
        if (segments.Length != 3)
            return null;

        var published = _keyRing.Current.Published;

        try
        {
            var key = ResolveSigningKey(segments[0], published);
            if (key is null || !HasValidSignature(key, idTokenHint, segments[2]))
                return null;

            return ReadClaims(segments[1], clientId);
        }
        catch (Exception ex) when (ex is FormatException or JsonException or CryptographicException)
        {
            // Malformed Base64Url, malformed JSON, or a signature the platform could not evaluate:
            // each means the same as a signature that did not verify.
            _ = ex;
            return null;
        }
    }

    /// <summary>
    /// The published key the header names, provided the header is one this server writes and
    /// names that key's own algorithm. Nothing is verified against a key the server does not
    /// publish, and the header never chooses how the signature is checked.
    /// </summary>
    private static SigningKey? ResolveSigningKey(string headerSegment, IReadOnlyList<SigningKey> published)
    {
        using var header = JsonDocument.Parse(Base64Url.DecodeFromChars(headerSegment));
        var root = header.RootElement;

        // A crit header lists extensions the recipient must understand; this server writes none.
        if (root.ValueKind != JsonValueKind.Object || root.TryGetProperty("crit", out _))
            return null;

        if (!string.Equals(ReadString(root, "typ"), IdTokenType, StringComparison.Ordinal))
            return null;

        var kid = ReadString(root, "kid");
        var algorithm = ReadString(root, "alg");
        if (kid is null || algorithm is null)
            return null;

        var key = published.FirstOrDefault(candidate => string.Equals(candidate.Kid, kid, StringComparison.Ordinal));

        return key is not null && string.Equals(SigningAlgorithms.WireName(key.Algorithm), algorithm, StringComparison.Ordinal)
            ? key
            : null;
    }

    private static bool HasValidSignature(SigningKey key, string idTokenHint, string signatureSegment)
    {
        var signingInput = Encoding.ASCII.GetBytes(idTokenHint, 0, idTokenHint.LastIndexOf('.'));

        return SigningAlgorithms.Verify(key.Algorithm, key.PublicKey, signingInput, Base64Url.DecodeFromChars(signatureSegment));
    }

    private IdTokenHint? ReadClaims(string payloadSegment, string? clientId)
    {
        using var payload = JsonDocument.Parse(Base64Url.DecodeFromChars(payloadSegment));
        var root = payload.RootElement;
        if (root.ValueKind != JsonValueKind.Object || !IsThisServer(ReadString(root, "iss")))
            return null;

        var subject = ReadString(root, "sub");
        var audience = ReadString(root, "aud");
        if (string.IsNullOrEmpty(subject) || !IsIssuedTo(audience, clientId))
            return null;

        return new IdTokenHint(audience, subject);
    }

    /// <summary>
    /// Whether the hint is worth reading at all. Only ASCII is accepted because every segment of a
    /// compact JWS is Base64Url, and the signing input is taken as the hint's ASCII bytes.
    /// </summary>
    private static bool IsReadable([NotNullWhen(true)] string? idTokenHint) =>
        !string.IsNullOrEmpty(idTokenHint) && idTokenHint.Length <= MaxLength && Ascii.IsValid(idTokenHint);

    private bool IsThisServer(string? issuer) =>
        !string.IsNullOrEmpty(issuer) && string.Equals(issuer, _options.Value.Issuer, StringComparison.Ordinal);

    /// <summary>
    /// Whether <paramref name="audience"/> names a client, and, when the request named one too,
    /// the same client.
    /// </summary>
    private static bool IsIssuedTo([NotNullWhen(true)] string? audience, string? clientId) =>
        !string.IsNullOrEmpty(audience)
        && (clientId is null || string.Equals(audience, clientId, StringComparison.Ordinal));

    private static string? ReadString(JsonElement element, string name) =>
        element.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.String
            ? value.GetString()
            : null;
}
