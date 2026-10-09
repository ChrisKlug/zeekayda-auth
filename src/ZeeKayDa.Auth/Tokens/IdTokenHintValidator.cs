using System.Diagnostics.CodeAnalysis;
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
/// <c>typ</c> <c>JWT</c>, signed by a key the source still lists, under that key's own algorithm,
/// carrying this server's <c>iss</c>, a <c>sub</c>, and a single-string <c>aud</c>. Neither the
/// token's lifetime nor whether its key is still published is checked: a relying party sends the ID
/// token it received at sign-in, which by the time the user signs out has usually expired and may
/// have been signed by a key since retired, and the hint only has to prove where it came from.
/// </remarks>
internal sealed class IdTokenHintValidator(SigningKeyRing keyRing, IOptions<AuthorizationServerOptions> options)
{
    private const string IdTokenType = "JWT";

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
        if (!CompactJws.TryParse(idTokenHint, out var jws) || !IsSignedIdToken(jws))
            return null;

        using var claims = JwtClaims.Parse(jws.Payload);
        if (claims is null || !IsThisServer(JwtClaims.ReadString(claims.RootElement, "iss")))
            return null;

        var subject = JwtClaims.ReadString(claims.RootElement, "sub");
        var audience = JwtClaims.ReadString(claims.RootElement, "aud");

        return string.IsNullOrEmpty(subject) || !IsIssuedTo(audience, clientId)
            ? null
            : new IdTokenHint(audience, subject);
    }

    /// <summary>
    /// An ID token by its <c>typ</c> (RFC 7515 §4.1.9: a media type, compared ignoring case), signed
    /// by a key this server lists, under that key's own algorithm.
    /// </summary>
    private bool IsSignedIdToken(CompactJws jws) =>
        string.Equals(jws.Typ, IdTokenType, StringComparison.OrdinalIgnoreCase)
        && keyRing.Verify(jws.Kid, jws.SigningInput.Span, jws.Signature.Span) is { } key
        && jws.NamesAlgorithmOf(key);

    private bool IsThisServer(string? issuer) =>
        !string.IsNullOrEmpty(issuer) && string.Equals(issuer, options.Value.Issuer, StringComparison.Ordinal);

    /// <summary>
    /// Whether <paramref name="audience"/> names a client, and, when the request named one too,
    /// the same client.
    /// </summary>
    private static bool IsIssuedTo([NotNullWhen(true)] string? audience, string? clientId) =>
        !string.IsNullOrEmpty(audience)
        && (clientId is null || string.Equals(audience, clientId, StringComparison.Ordinal));
}
