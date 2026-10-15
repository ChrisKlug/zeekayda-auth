using System.Diagnostics.CodeAnalysis;
using Microsoft.Extensions.Options;

namespace ZeeKayDa.Auth.Tokens;

/// <summary>The client and user named by an <c>id_token_hint</c> proven to be one of this server's ID tokens.</summary>
internal sealed record IdTokenHint(string ClientId, string Subject);

/// <summary>Decides whether an <c>id_token_hint</c> is an ID token this server issued, and whom it names.</summary>
/// <remarks>
/// Lifetime and publication are not checked: a relying party sends the ID token it got at sign-in, often
/// expired by sign-out, and the hint only has to prove where it came from.
/// </remarks>
internal sealed class IdTokenHintValidator(SigningKeyRing keyRing, IOptions<AuthorizationServerOptions> options)
{
    private const string IdTokenType = "JWT";

    /// <summary>
    /// The client and user <paramref name="idTokenHint"/> names, or <see langword="null"/> when it is absent or
    /// not this server's; why is never reported.
    /// </summary>
    /// <param name="idTokenHint">The <c>id_token_hint</c> request parameter, verbatim.</param>
    /// <param name="clientId">
    /// The <c>client_id</c> request parameter, when the request carried one. A hint issued to any
    /// other client is refused.
    /// </param>
    /// <exception cref="InvalidOperationException">
    /// The signing key ring has not completed startup initialization.
    /// </exception>
    /// <exception cref="ObjectDisposedException">The signing key ring has been disposed.</exception>
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

    /// <summary>Signed by a listed key under its own algorithm, with <c>typ</c> <c>JWT</c> compared ignoring case (RFC 7515 §4.1.9).</summary>
    private bool IsSignedIdToken(CompactJws jws) =>
        string.Equals(jws.Typ, IdTokenType, StringComparison.OrdinalIgnoreCase)
        && keyRing.Verify(jws.Kid, jws.SigningInput.Span, jws.Signature.Span) is { } key
        && jws.NamesAlgorithmOf(key);

    private bool IsThisServer(string? issuer) =>
        !string.IsNullOrEmpty(issuer) && string.Equals(issuer, options.Value.Issuer, StringComparison.Ordinal);

    /// <summary>Whether <paramref name="audience"/> names a client, and the request's client when it named one.</summary>
    private static bool IsIssuedTo([NotNullWhen(true)] string? audience, string? clientId) =>
        !string.IsNullOrEmpty(audience)
        && (clientId is null || string.Equals(audience, clientId, StringComparison.Ordinal));
}
