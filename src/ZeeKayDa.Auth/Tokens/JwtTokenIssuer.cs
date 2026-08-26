using System.Buffers;
using System.Buffers.Text;
using System.Text;
using System.Text.Json;

namespace ZeeKayDa.Auth.Tokens;

/// <summary>
/// The <see cref="ITokenIssuer"/> that issues JWTs: serializes the payload's claims to JSON, signs
/// them through the <see cref="ISigningKeyRing"/>, and assembles the RFC 7515 §5.1 compact
/// serialization.
/// </summary>
/// <remarks>
/// <para>
/// The JOSE header is built <em>inside</em> the ring's signing callback, from the
/// <see cref="SigningKey"/> the ring resolved for that call. The key is resolved exactly once per
/// token, and the header's <c>kid</c> and <c>alg</c> are read from the same resolved key that
/// produces the signature — a header that disagrees with its signature is unrepresentable rather
/// than merely detected.
/// </para>
/// <para>
/// The <c>typ</c> header follows the profile for the kind being issued: <c>at+jwt</c> for access
/// tokens (RFC 9068 §2.1), <c>JWT</c> for ID tokens.
/// </para>
/// </remarks>
public sealed class JwtTokenIssuer : ITokenIssuer
{
    private const string AccessTokenType = "at+jwt";
    private const string IdTokenType = "JWT";

    private readonly ISigningKeyRing _ring;

    /// <summary>
    /// Initializes a new instance of the <see cref="JwtTokenIssuer"/> class.
    /// </summary>
    /// <param name="ring">The ring that resolves the signing key and signs.</param>
    /// <exception cref="ArgumentNullException">
    /// Thrown when <paramref name="ring"/> is <see langword="null"/>.
    /// </exception>
    public JwtTokenIssuer(ISigningKeyRing ring)
    {
        ArgumentNullException.ThrowIfNull(ring);
        _ring = ring;
    }

    /// <inheritdoc/>
    /// <exception cref="ArgumentNullException">
    /// Thrown when <paramref name="payload"/> is <see langword="null"/>.
    /// </exception>
    /// <exception cref="ArgumentOutOfRangeException">
    /// Thrown when <paramref name="context"/>.Kind is not a defined <see cref="TokenKind"/> member.
    /// </exception>
    public async ValueTask<IssuedToken> IssueAsync(
        TokenIssuanceContext context,
        TokenPayload payload,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(payload);

        var typ = context.Kind switch
        {
            TokenKind.AccessToken => AccessTokenType,
            TokenKind.IdToken => IdTokenType,
            _ => throw new ArgumentOutOfRangeException(
                nameof(context), context.Kind, $"Not a defined {nameof(TokenKind)} member."),
        };

        // Claim names and values are serialized verbatim — selection and naming happened before
        // TokenPayload was constructed, and a naming policy here would silently rewrite them.
        var payloadSegment = Base64Url.EncodeToString(
            JsonSerializer.SerializeToUtf8Bytes(payload.Claims));

        var outcome = await _ring.SignAsync(
            (payloadSegment, typ),
            static (signing, state) => BuildSigningInput(signing.Key, state.payloadSegment, state.typ),
            cancellationToken).ConfigureAwait(false);

        var token = string.Create(
            outcome.SigningInput.Length + 1 + Base64Url.GetEncodedLength(outcome.Signature.Length),
            outcome,
            static (destination, outcome) =>
            {
                var written = Encoding.ASCII.GetChars(outcome.SigningInput.Span, destination);
                destination[written] = '.';
                Base64Url.EncodeToChars(outcome.Signature.Span, destination[(written + 1)..]);
            });

        return new IssuedToken(token, context.Kind);
    }

    // Runs inside the ring's signing callback: the header is built from the key the ring resolved
    // for this exact call, so kid/alg and the signature can never come from different keys.
    private static ReadOnlyMemory<byte> BuildSigningInput(SigningKey key, string payloadSegment, string typ)
    {
        var buffer = new ArrayBufferWriter<byte>();
        using (var writer = new Utf8JsonWriter(buffer))
        {
            writer.WriteStartObject();
            // SigningAlgorithm member names are the RFC 7518 identifiers verbatim.
            writer.WriteString("alg", key.Algorithm.ToString());
            writer.WriteString("typ", typ);
            writer.WriteString("kid", key.Kid);
            writer.WriteEndObject();
        }

        var headerSegment = Base64Url.EncodeToString(buffer.WrittenSpan);
        return Encoding.ASCII.GetBytes($"{headerSegment}.{payloadSegment}");
    }
}
