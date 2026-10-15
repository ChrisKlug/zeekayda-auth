using System.Buffers;
using System.Buffers.Text;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace ZeeKayDa.Auth.Tokens;

/// <summary>
/// The <see cref="ITokenIssuer"/> that issues JWTs: serializes the payload's claims to JSON, signs
/// them through the <see cref="SigningKeyRing"/>, and assembles the RFC 7515 §5.1 compact
/// serialization.
/// </summary>
/// <remarks>
/// <para>
/// The JOSE header is built inside the ring's signing callback from the key it resolved, once per token,
/// so its <c>kid</c> and <c>alg</c> cannot disagree with the signature.
/// </para>
/// <para>
/// For an ID token the same callback computes <c>at_hash</c> with the hash the key's algorithm implies
/// (OpenID Connect Core §3.1.3.6) and checks the client's
/// <see cref="Clients.IClient.AllowedSigningAlgorithms"/> before the signer is touched. Those are all this
/// issuer adds; every other claim is written verbatim.
/// </para>
/// <para>
/// The <c>typ</c> header is <c>at+jwt</c> for access tokens (RFC 9068 §2.1) and <c>JWT</c> for ID tokens.
/// </para>
/// </remarks>
public sealed class JwtTokenIssuer : ITokenIssuer
{
    private const string AccessTokenType = "at+jwt";
    private const string IdTokenType = "JWT";
    private const string AccessTokenHashClaim = "at_hash";

    private readonly SigningKeyRing _ring;

    /// <summary>
    /// Initializes a new instance of the <see cref="JwtTokenIssuer"/> class.
    /// </summary>
    /// <param name="keyRing">The ring that resolves the signing key and signs.</param>
    /// <exception cref="ArgumentNullException">
    /// Thrown when <paramref name="keyRing"/> is <see langword="null"/>.
    /// </exception>
    public JwtTokenIssuer(SigningKeyRing keyRing)
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
    /// <see cref="Clients.IClient.AllowedSigningAlgorithms"/> excludes the algorithm of the
    /// key the ring resolved for an ID token.
    /// </exception>
    /// <exception cref="System.Text.Json.JsonException">
    /// Thrown when a claim value cannot be serialized — a reference cycle, or a type
    /// System.Text.Json does not support. See <see cref="TokenPayload"/> for what claim values
    /// may be.
    /// </exception>
    public async Task<IssuedToken> IssueAsync(
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

        return new IssuedToken(CompactJws.Serialize(outcome.SigningInput.Span, outcome.Signature.Span), kind);
    }

    /// <summary>
    /// The access token to bind, refused when the payload already carries <c>at_hash</c> or the token is not the
    /// ASCII octets a relying party hashes (OpenID Connect Core §3.1.3.6).
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

        if (!Ascii.IsValid(accessToken.Value))
        {
            throw new InvalidOperationException(
                "The access token an ID token is bound to must be ASCII, as every bearer token on the " +
                "wire is; a value outside ASCII has no at_hash a relying party could verify.");
        }

        return accessToken.Value;
    }

    private static ReadOnlyMemory<byte> BuildSigningInput(SigningKey key, SigningState state)
    {
        var accessToken = state.AccessTokenToBind;
        if (accessToken is not null)
            RequireAlgorithmAllowed(state.Context, key);

        var payload = Payload(state.Payload, accessToken is null ? null : AccessTokenHash(key.Algorithm, accessToken));
        return CompactJws.BuildSigningInput(key, state.Typ, payload);
    }

    /// <summary>Refuses an ID token outside the client's algorithms here, rather than leave the client to reject it.</summary>
    private static void RequireAlgorithmAllowed(TokenIssuanceContext context, SigningKey key)
    {
        if (context.Client.AllowedSigningAlgorithms is { } allowed && !allowed.Contains(key.Algorithm))
        {
            throw new InvalidOperationException(
                $"Client '{context.Client.ClientId}' does not allow ID tokens signed with " +
                $"{SigningAlgorithms.WireName(key.Algorithm)}, the algorithm the server signs with. " +
                "Widen the client's AllowedSigningAlgorithms, or register a signing source for an algorithm it allows.");
        }
    }

    // Verbatim: a naming policy here would silently rewrite claim names chosen upstream.
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

    /// <summary>The left half of the access token's hash under the key's algorithm, base64url (OpenID Connect Core §3.1.3.6).</summary>
    private static string AccessTokenHash(SigningAlgorithm algorithm, string accessToken)
    {
        var digest = CryptographicOperations.HashData(SigningAlgorithms.HashAlgorithm(algorithm), Encoding.ASCII.GetBytes(accessToken));
        return Base64Url.EncodeToString(digest.AsSpan(0, digest.Length / 2));
    }

    private readonly record struct SigningState(TokenIssuanceContext Context, TokenPayload Payload, string Typ, string? AccessTokenToBind);
}
