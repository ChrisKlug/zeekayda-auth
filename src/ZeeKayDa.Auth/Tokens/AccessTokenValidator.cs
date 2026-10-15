using System.Text.Json;
using Microsoft.Extensions.Options;

namespace ZeeKayDa.Auth.Tokens;

/// <summary>A live access token of this server's, and the three things a protected resource here needs from it.</summary>
internal sealed record ValidatedAccessToken(string Subject, string ClientId, IReadOnlyList<string> Scopes);

/// <summary>A NumericDate claim as read from a payload: whether it was written, and what it says.</summary>
internal readonly record struct NumericDate(bool Present, DateTimeOffset? Value)
{
    public static NumericDate Absent => new(false, null);

    public static NumericDate Unreadable => new(true, null);

    /// <summary>The issuer wrote the claim and this code cannot tell what instant it names.</summary>
    public bool IsUnreadable => Present && Value is null;
}

/// <summary>
/// Validates an access token as RFC 9068 §4 obliges a resource server to: signature, <c>typ</c>,
/// <c>iss</c>, an <c>aud</c> naming this server, and a live validity window.
/// </summary>
internal sealed class AccessTokenValidator(
    SigningKeyRing keyRing,
    IOptions<AuthorizationServerOptions> options,
    TimeProvider time)
{
    // RFC 9068 §2.1 fixes the typ as "at+jwt"; the media-type form is the same registration.
    private static readonly string[] AccessTokenTypes = ["at+jwt", "application/at+jwt"];

    /// <summary>
    /// What <paramref name="accessToken"/> names when it is a live access token of this server's, else
    /// <see langword="null"/>; which check failed is never reported.
    /// </summary>
    /// <param name="accessToken">The presented bearer token, verbatim.</param>
    /// <exception cref="InvalidOperationException">
    /// The signing key ring has not completed startup initialization.
    /// </exception>
    /// <exception cref="ObjectDisposedException">The signing key ring has been disposed.</exception>
    public ValidatedAccessToken? Validate(string? accessToken)
    {
        if (!CompactJws.TryParse(accessToken, out var jws) || !IsSignedAccessToken(jws))
            return null;

        using var claims = JwtClaims.Parse(jws.Payload);
        return claims is null ? null : ReadVerified(claims.RootElement);
    }

    /// <summary>What a verified token names, when it is this server's, addressed to it, and live.</summary>
    private ValidatedAccessToken? ReadVerified(JsonElement claims)
    {
        var issuer = options.Value.Issuer;

        if (!string.Equals(JwtClaims.ReadString(claims, "iss"), issuer, StringComparison.Ordinal))
            return null;

        if (!NamesThisServer(claims, issuer) || !IsWithinValidityWindow(claims))
            return null;

        var subject = JwtClaims.ReadString(claims, "sub");
        var clientId = JwtClaims.ReadString(claims, "client_id");

        return string.IsNullOrEmpty(subject) || string.IsNullOrEmpty(clientId)
            ? null
            : new ValidatedAccessToken(subject, clientId, ReadScopes(claims));
    }

    /// <summary>Signed by a listed key under its own algorithm, with an access-token <c>typ</c>; publication does not matter.</summary>
    private bool IsSignedAccessToken(CompactJws jws) =>
        AccessTokenTypes.Contains(jws.Typ, StringComparer.OrdinalIgnoreCase)
        && keyRing.Verify(jws.Kid, jws.SigningInput.Span, jws.Signature.Span) is { } key
        && jws.NamesAlgorithmOf(key);

    /// <summary>Whether <c>aud</c>, a string or an array (RFC 7519 §4.1.3), names this server (RFC 9068 §4).</summary>
    private static bool NamesThisServer(JsonElement payload, string? issuer)
    {
        if (!payload.TryGetProperty("aud", out var audience))
            return false;

        return audience.ValueKind == JsonValueKind.Array
            ? audience.EnumerateArray().Any(entry => IsIssuer(entry, issuer))
            : IsIssuer(audience, issuer);
    }

    private static bool IsIssuer(JsonElement value, string? issuer) =>
        JwtClaims.AsString(value) is { } name && string.Equals(name, issuer, StringComparison.Ordinal);

    /// <summary>
    /// A readable <c>exp</c> not passed (RFC 9068 §2.2) and any <c>nbf</c> reached, both readable, within the
    /// clock-skew tolerance. The tolerance is applied to the clock, never the claim, which may sit at the edge of
    /// <see cref="DateTimeOffset"/>.
    /// </summary>
    private bool IsWithinValidityWindow(JsonElement payload)
    {
        if (ReadNumericDate(payload, "exp").Value is not { } expiresAt)
            return false;

        var notBefore = ReadNumericDate(payload, "nbf");
        if (notBefore.IsUnreadable)
            return false;

        var now = time.GetUtcNow();
        var skew = options.Value.ClockSkewTolerance;

        return now - skew <= expiresAt
            && (notBefore.Value is not { } validFrom || now + skew >= validFrom);
    }

    /// <summary>A NumericDate claim: absent, present but unreadable, or an instant.</summary>
    private static NumericDate ReadNumericDate(JsonElement payload, string name)
    {
        if (!payload.TryGetProperty(name, out var value))
            return NumericDate.Absent;

        if (value.ValueKind != JsonValueKind.Number || !value.TryGetInt64(out var seconds))
            return NumericDate.Unreadable;

        try
        {
            return new NumericDate(true, DateTimeOffset.FromUnixTimeSeconds(seconds));
        }
        catch (ArgumentOutOfRangeException)
        {
            // Outside the representable range: written, and unreadable.
            return NumericDate.Unreadable;
        }
    }

    /// <summary>The space-delimited <c>scope</c> claim (RFC 9068 §2.2.3); none when absent.</summary>
    private static IReadOnlyList<string> ReadScopes(JsonElement payload) =>
        JwtClaims.ReadString(payload, "scope") is { } scope
            ? scope.Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            : [];
}
