using ZeeKayDa.Auth.Claims;
using ZeeKayDa.Auth.Clients;
using ZeeKayDa.Auth.Stores;

namespace ZeeKayDa.Auth.Tokens;

/// <summary>
/// The claims of the tokens an authorization code becomes: protocol claims from the grant, never the
/// request, subject claims from one resolution, and one issuance instant for both.
/// </summary>
internal sealed class CodeGrantTokenPayloads
{
    private readonly string _issuer;
    private readonly IClient _client;
    private readonly AuthorizationCodeEntry _entry;
    private readonly DateTimeOffset _now;
    private readonly SelectedClaims _subject;
    private readonly string? _resourceAudience;

    /// <summary>Binds one issuance's grant, client, instant and selected subject claims, from which both payloads are built.</summary>
    /// <param name="issuer">The issuer, always an audience of the access token.</param>
    /// <param name="client">The client the tokens are for.</param>
    /// <param name="entry">The redeemed grant.</param>
    /// <param name="now">The one issuance instant both tokens share.</param>
    /// <param name="subject">The subject claims, selected per destination from one resolution.</param>
    /// <param name="resourceAudience">
    /// The resource server the granted scopes name, or <see langword="null"/> when they name
    /// none, in which case the issuer is the access token's only audience.
    /// </param>
    public CodeGrantTokenPayloads(
        string issuer,
        IClient client,
        AuthorizationCodeEntry entry,
        DateTimeOffset now,
        SelectedClaims subject,
        string? resourceAudience)
    {
        ArgumentException.ThrowIfNullOrEmpty(issuer);
        ArgumentNullException.ThrowIfNull(client);
        ArgumentNullException.ThrowIfNull(entry);
        ArgumentNullException.ThrowIfNull(subject);

        _issuer = issuer;
        _client = client;
        _entry = entry;
        _now = now;
        _subject = subject;
        _resourceAudience = resourceAudience;
    }

    /// <summary>
    /// The access token's claims (RFC 9068 §2.2). Its audience is the resource server the
    /// granted scopes name together with the issuer, or the issuer alone: <c>openid</c> is
    /// always granted, and userinfo is a resource the issuer hosts (RFC 9068 §3, §4).
    /// </summary>
    public PreparedPayload AccessToken(TimeSpan lifetime, string jti)
    {
        ArgumentException.ThrowIfNullOrEmpty(jti);

        var expiresAt = TokenLifetimes.ExpiresAt(_now, lifetime);
        var claims = new Dictionary<string, object?>(StringComparer.Ordinal)
        {
            ["iss"] = _issuer,
            ["sub"] = _entry.Sub,
            ["aud"] = AccessTokenAudience(),
            ["client_id"] = _client.ClientId,
            ["iat"] = _now.ToUnixTimeSeconds(),
            ["exp"] = expiresAt.ToUnixTimeSeconds(),
            ["jti"] = jti,
            ["scope"] = string.Join(' ', _entry.Scope),
        };
        AddAuthenticationEvent(claims);
        AddSubjectClaims(claims, _subject.AccessToken);

        return new PreparedPayload(new TokenPayload(claims), expiresAt);
    }

    /// <summary>
    /// The ID token's claims (OIDC Core §2): one audience, the requesting client, and the
    /// request's <c>nonce</c> whenever it carried one.
    /// </summary>
    public PreparedPayload IdToken(TimeSpan lifetime)
    {
        var expiresAt = TokenLifetimes.ExpiresAt(_now, lifetime);
        var claims = new Dictionary<string, object?>(StringComparer.Ordinal)
        {
            ["iss"] = _issuer,
            ["sub"] = _entry.Sub,
            ["aud"] = _client.ClientId,
            ["iat"] = _now.ToUnixTimeSeconds(),
            ["exp"] = expiresAt.ToUnixTimeSeconds(),
        };
        AddAuthenticationEvent(claims);

        if (_entry.Nonce is { } nonce)
            claims["nonce"] = nonce;

        AddSubjectClaims(claims, _subject.IdToken);

        return new PreparedPayload(new TokenPayload(claims), expiresAt);
    }

    /// <summary>
    /// A single string for one recipient, an array for two (RFC 7519 §4.1.3). A scope whose
    /// audience is the issuer itself names one recipient, not the same one twice.
    /// </summary>
    private object AccessTokenAudience() =>
        _resourceAudience is null || string.Equals(_resourceAudience, _issuer, StringComparison.Ordinal)
            ? _issuer
            : new[] { _resourceAudience, _issuer };

    /// <summary>
    /// The original authentication event, on both tokens (RFC 9068 §2.2.1): <c>auth_time</c>
    /// always, <c>acr</c> and <c>amr</c> when the grant carries them and never as <c>null</c>.
    /// </summary>
    private void AddAuthenticationEvent(Dictionary<string, object?> claims)
    {
        claims["auth_time"] = _entry.AuthTime.ToUnixTimeSeconds();

        if (_entry.Acr is { } acr)
            claims["acr"] = acr;

        if (_entry.Amr is { Count: > 0 } amr)
            claims["amr"] = amr.ToArray();
    }

    /// <summary>
    /// Added, never assigned: a subject claim with a protocol claim's name means selection failed, and fails
    /// issuance rather than overwrite the grant.
    /// </summary>
    private static void AddSubjectClaims(Dictionary<string, object?> claims, IReadOnlyDictionary<string, ClaimValue> subject)
    {
        foreach (var (name, value) in subject)
            claims.Add(name, value);
    }
}

/// <summary>A finalized payload and the expiry it carries, so the response's <c>expires_in</c> cannot disagree with <c>exp</c>.</summary>
internal readonly record struct PreparedPayload(TokenPayload Payload, DateTimeOffset ExpiresAt);
