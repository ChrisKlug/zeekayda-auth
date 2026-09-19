using System.Text.Json;
using Microsoft.Extensions.Options;

namespace ZeeKayDa.Auth.Tokens;

/// <summary>
/// An access token this server issued, proven live and addressed to this server, and the three
/// things a protected resource here needs from it.
/// </summary>
/// <param name="Subject">The user the token was issued for: its <c>sub</c>.</param>
/// <param name="ClientId">The client the token was issued to: its <c>client_id</c>.</param>
/// <param name="Scopes">The scopes the grant carries, in the order the token lists them.</param>
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
/// Validates an access token the way RFC 9068 §4 obliges a resource server to: this server's
/// signature, its <c>typ</c>, its <c>iss</c>, an <c>aud</c> naming this server, and a validity
/// window that has not passed.
/// </summary>
/// <remarks>
/// The issuer is always an audience of an access token carrying <c>openid</c>, which is what lets
/// a resource this server hosts validate one as an ordinary resource server rather than by
/// trusting <c>iss</c> alone. What the token then authorizes — which scopes a given endpoint
/// requires — is the endpoint's question, not this type's.
/// </remarks>
internal sealed class AccessTokenValidator
{
    // RFC 9068 §2.1 fixes the typ as "at+jwt"; the media-type form is the same registration, and
    // a host that replaced ITokenIssuer may write it.
    private static readonly string[] AccessTokenTypes = ["at+jwt", "application/at+jwt"];

    private readonly ISigningKeyRing _keyRing;
    private readonly IOptions<AuthorizationServerOptions> _options;
    private readonly TimeProvider _time;

    public AccessTokenValidator(
        ISigningKeyRing keyRing,
        IOptions<AuthorizationServerOptions> options,
        TimeProvider time)
    {
        ArgumentNullException.ThrowIfNull(keyRing);
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(time);

        _keyRing = keyRing;
        _options = options;
        _time = time;
    }

    /// <summary>
    /// Returns what <paramref name="accessToken"/> names when it is a live access token of this
    /// server's, or <see langword="null"/> when it is absent, malformed, unsigned by this server,
    /// expired, not yet valid, or addressed elsewhere. Which of those it was is never reported.
    /// </summary>
    /// <param name="accessToken">The presented bearer token, verbatim.</param>
    /// <exception cref="InvalidOperationException">
    /// The signing key ring has not completed startup initialization.
    /// </exception>
    public ValidatedAccessToken? Validate(string? accessToken)
    {
        using var payload = SignedTokenReader.Verify(accessToken, AccessTokenTypes, _keyRing.Current.Published);
        if (payload is null)
            return null;

        var root = payload.RootElement;
        var issuer = _options.Value.Issuer;

        if (!string.Equals(SignedTokenReader.ReadString(root, "iss"), issuer, StringComparison.Ordinal))
            return null;

        if (!NamesThisServer(root, issuer) || !IsWithinValidityWindow(root))
            return null;

        var subject = SignedTokenReader.ReadString(root, "sub");
        var clientId = SignedTokenReader.ReadString(root, "client_id");

        return string.IsNullOrEmpty(subject) || string.IsNullOrEmpty(clientId)
            ? null
            : new ValidatedAccessToken(subject, clientId, ReadScopes(root));
    }

    /// <summary>
    /// RFC 9068 §4: a resource server rejects a token whose <c>aud</c> does not name it. The claim
    /// is a single string for one recipient and an array for several (RFC 7519 §4.1.3); a token
    /// carrying neither shape names nobody and is refused.
    /// </summary>
    private static bool NamesThisServer(JsonElement payload, string? issuer)
    {
        if (!payload.TryGetProperty("aud", out var audience))
            return false;

        return audience.ValueKind switch
        {
            JsonValueKind.String => string.Equals(audience.GetString(), issuer, StringComparison.Ordinal),
            JsonValueKind.Array => audience.EnumerateArray().Any(entry =>
                entry.ValueKind == JsonValueKind.String &&
                string.Equals(entry.GetString(), issuer, StringComparison.Ordinal)),
            _ => false,
        };
    }

    /// <summary>
    /// The token has not expired and has become valid, each allowed the configured clock-skew
    /// tolerance. <c>exp</c> is required of an access token (RFC 9068 §2.2), so a token without a
    /// readable one is refused rather than treated as eternal; <c>nbf</c> is honoured when present
    /// (RFC 7519 §4.1.5), and one present but unreadable is refused rather than ignored, since a
    /// token says it becomes valid later and this code cannot tell when.
    /// </summary>
    /// <remarks>
    /// The tolerance is applied to <see cref="TimeProvider.GetUtcNow"/>, never to the claim.
    /// <c>exp</c> and <c>nbf</c> come off the wire and may sit at the edge of what
    /// <see cref="DateTimeOffset"/> represents — the framework itself emits the maximum when an
    /// operator configures an enormous lifetime — where adding to them overflows. The clock is
    /// always far from either edge, and validation is bounded to well under an hour.
    /// </remarks>
    private bool IsWithinValidityWindow(JsonElement payload)
    {
        if (ReadNumericDate(payload, "exp").Value is not { } expiresAt)
            return false;

        var notBefore = ReadNumericDate(payload, "nbf");
        if (notBefore.IsUnreadable)
            return false;

        var now = _time.GetUtcNow();
        var skew = _options.Value.ClockSkewTolerance;

        return now - skew <= expiresAt
            && (notBefore.Value is not { } validFrom || now + skew >= validFrom);
    }

    /// <summary>
    /// A NumericDate claim (RFC 7519 §2): absent, present but unreadable, or an instant. The
    /// middle case is distinct because a claim the issuer wrote and this code cannot read is not
    /// the same as one the issuer never wrote.
    /// </summary>
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

    /// <summary>
    /// The <c>scope</c> claim as the space-delimited list RFC 9068 §2.2.3 writes. A token without
    /// one carries no scopes, which unlocks nothing.
    /// </summary>
    private static IReadOnlyList<string> ReadScopes(JsonElement payload) =>
        SignedTokenReader.ReadString(payload, "scope") is { } scope
            ? scope.Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            : [];
}
