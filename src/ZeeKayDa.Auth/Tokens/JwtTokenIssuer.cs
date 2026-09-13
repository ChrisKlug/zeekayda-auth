using System.Buffers;
using System.Buffers.Text;
using System.Security.Cryptography;
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
/// An ID token is bound to the access token issued with it: <c>at_hash</c> is computed inside the
/// same callback, with the hash function the resolved key's algorithm implies (OpenID Connect Core
/// §3.1.3.6), and the client's <see cref="Clients.IClientMetadata.AllowedSigningAlgorithms"/> is
/// checked there against that key before the signer is touched. Those two are everything this
/// issuer adds to a payload; every other claim is written verbatim.
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
    private const string AccessTokenHashClaim = "at_hash";

    private readonly ISigningKeyRing _ring;

    /// <summary>
    /// Initializes a new instance of the <see cref="JwtTokenIssuer"/> class.
    /// </summary>
    /// <param name="keyRing">The ring that resolves the signing key and signs.</param>
    /// <exception cref="ArgumentNullException">
    /// Thrown when <paramref name="keyRing"/> is <see langword="null"/>.
    /// </exception>
    public JwtTokenIssuer(ISigningKeyRing keyRing)
    {
        ArgumentNullException.ThrowIfNull(keyRing);
        _ring = keyRing;
    }

    /// <inheritdoc/>
    /// <exception cref="ArgumentNullException">
    /// Thrown when <paramref name="context"/> or <paramref name="payload"/> is <see langword="null"/>.
    /// </exception>
    /// <exception cref="InvalidOperationException">
    /// Thrown, before anything is signed, when the access token an ID token is bound to is not
    /// ASCII, when <paramref name="payload"/> already carries <c>at_hash</c>, or when the client's
    /// <see cref="Clients.IClientMetadata.AllowedSigningAlgorithms"/> excludes the algorithm of the
    /// key the ring resolved for an ID token.
    /// </exception>
    /// <exception cref="System.Text.Json.JsonException">
    /// Thrown when a claim value cannot be serialized — a reference cycle, or a type
    /// System.Text.Json does not support. See <see cref="TokenPayload"/> for what claim values
    /// may be.
    /// </exception>
    public async ValueTask<IssuedToken> IssueAsync(
        TokenIssuanceContext context,
        TokenPayload payload,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(payload);

        // The type says which token this is; the hierarchy is closed, so these are the two cases.
        var (kind, typ, accessTokenToBind) = context is IdTokenIssuanceContext idToken
            ? (TokenKind.IdToken, IdTokenType, RequireAccessToken(idToken, payload))
            : (TokenKind.AccessToken, AccessTokenType, null);

        var outcome = await _ring.SignAsync(
            new SigningState(context, payload, typ, accessTokenToBind),
            static (signing, state) => BuildSigningInput(signing.Key, state),
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

        return new IssuedToken(token, kind);
    }

    /// <summary>
    /// The payload must not already claim to carry the hash, since the value written here is the
    /// only one that can agree with the key that signs; and the access token it hashes must be
    /// the ASCII octets a relying party will hash too.
    /// </summary>
    private static string RequireAccessToken(IdTokenIssuanceContext context, TokenPayload payload)
    {
        var accessToken = context.AccessToken;

        if (payload.Claims.ContainsKey(AccessTokenHashClaim))
        {
            throw new InvalidOperationException(
                $"The payload already carries '{AccessTokenHashClaim}'. The issuer computes it from the key " +
                "that signs, and a payload value could not agree with that key.");
        }

        // The hash is over the token's ASCII octets (OpenID Connect Core §3.1.3.6). A value that
        // is not ASCII has no octets a relying party could reproduce, so it is refused rather than
        // hashed with substitutions.
        if (!Ascii.IsValid(accessToken.Value))
        {
            throw new InvalidOperationException(
                "The access token an ID token is bound to must be ASCII, as every bearer token on the " +
                "wire is; a value outside ASCII has no at_hash a relying party could verify.");
        }

        return accessToken.Value;
    }

    // Runs inside the ring's signing callback: the header is built from the key the ring resolved
    // for this exact call, so kid/alg and the signature can never come from different keys — and
    // for an ID token, so can neither at_hash nor the client's algorithm policy.
    private static ReadOnlyMemory<byte> BuildSigningInput(SigningKey key, SigningState state)
    {
        var accessToken = state.AccessTokenToBind;
        if (accessToken is not null)
            RequireAlgorithmAllowed(state.Context, key);

        var headerSegment = Base64Url.EncodeToString(Header(key, state.Typ));
        var payloadSegment = Base64Url.EncodeToString(Payload(
            state.Payload,
            accessToken is null ? null : AccessTokenHash(key.Algorithm, accessToken)));

        return Encoding.ASCII.GetBytes($"{headerSegment}.{payloadSegment}");
    }

    /// <summary>
    /// A client that restricted its ID-token algorithms is refused a token outside them, here,
    /// before the signer is touched; the client would have rejected it anyway, and a fault at this
    /// end beats a silent one at theirs.
    /// </summary>
    private static void RequireAlgorithmAllowed(TokenIssuanceContext context, SigningKey key)
    {
        if (context.Client.AllowedSigningAlgorithms is { } allowed && !allowed.Contains(key.Algorithm))
        {
            throw new InvalidOperationException(
                $"Client '{context.Client.ClientId}' does not allow ID tokens signed with " +
                $"{SigningAlgorithms.WireName(key.Algorithm)}, the algorithm of the current signing key. " +
                "Widen the client's AllowedSigningAlgorithms, or sign with a key it allows.");
        }
    }

    private static ReadOnlySpan<byte> Header(SigningKey key, string typ)
    {
        var buffer = new ArrayBufferWriter<byte>();
        using (var writer = new Utf8JsonWriter(buffer))
        {
            writer.WriteStartObject();
            writer.WriteString("alg", SigningAlgorithms.WireName(key.Algorithm));
            writer.WriteString("typ", typ);
            writer.WriteString("kid", key.Kid);
            writer.WriteEndObject();
        }

        return buffer.WrittenSpan;
    }

    // Claim names and values are serialized verbatim — selection and naming happened before
    // TokenPayload was constructed, and a naming policy here would silently rewrite them. One
    // path for both kinds: the ID token's at_hash is the only addition, written last.
    private static ReadOnlySpan<byte> Payload(TokenPayload payload, string? accessTokenHash)
    {
        var buffer = new ArrayBufferWriter<byte>();
        using (var writer = new Utf8JsonWriter(buffer))
        {
            writer.WriteStartObject();
            foreach (var (name, value) in payload.Claims)
            {
                writer.WritePropertyName(name);
                JsonSerializer.Serialize(writer, value);
            }

            if (accessTokenHash is not null)
                writer.WriteString(AccessTokenHashClaim, accessTokenHash);

            writer.WriteEndObject();
        }

        return buffer.WrittenSpan;
    }

    /// <summary>
    /// OpenID Connect Core §3.1.3.6: the left half of the hash of the access token's ASCII wire
    /// value, base64url-encoded, using the hash algorithm of the ID token's <c>alg</c> — the one
    /// mapping the signer itself uses, with no fallback.
    /// </summary>
    private static string AccessTokenHash(SigningAlgorithm algorithm, string accessToken)
    {
        var digest = CryptographicOperations.HashData(SigningAlgorithms.HashAlgorithm(algorithm), Encoding.ASCII.GetBytes(accessToken));
        return Base64Url.EncodeToString(digest.AsSpan(0, digest.Length / 2));
    }

    private readonly record struct SigningState(TokenIssuanceContext Context, TokenPayload Payload, string Typ, string? AccessTokenToBind);
}
