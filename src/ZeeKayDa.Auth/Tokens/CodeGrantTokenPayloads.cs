using ZeeKayDa.Auth.Clients;
using ZeeKayDa.Auth.Stores;

namespace ZeeKayDa.Auth.Tokens;

/// <summary>
/// The protocol claims of the tokens an authorization code becomes. Every value comes from the
/// grant — the redeemed entry, the issuer, the client — never from the request that redeemed it,
/// and both tokens share one issuance instant, so their <c>iat</c> agree and each <c>exp</c> is
/// structurally at or after it.
/// </summary>
internal sealed class CodeGrantTokenPayloads
{
    private readonly string _issuer;
    private readonly IClientMetadata _client;
    private readonly AuthorizationCodeEntry _entry;
    private readonly DateTimeOffset _now;

    public CodeGrantTokenPayloads(string issuer, IClientMetadata client, AuthorizationCodeEntry entry, DateTimeOffset now)
    {
        ArgumentException.ThrowIfNullOrEmpty(issuer);
        ArgumentNullException.ThrowIfNull(client);
        ArgumentNullException.ThrowIfNull(entry);

        _issuer = issuer;
        _client = client;
        _entry = entry;
        _now = now;
    }

    /// <summary>
    /// The access token's claims (RFC 9068 §2.2): the issuer is its audience, since <c>openid</c>
    /// is always granted and userinfo is a resource the issuer hosts.
    /// </summary>
    public PreparedPayload AccessToken(TimeSpan lifetime, string jti)
    {
        ArgumentException.ThrowIfNullOrEmpty(jti);

        var expiresAt = TokenLifetimes.ExpiresAt(_now, lifetime);
        var claims = new Dictionary<string, object?>(StringComparer.Ordinal)
        {
            ["iss"] = _issuer,
            ["sub"] = _entry.Sub,
            ["aud"] = _issuer,
            ["client_id"] = _client.ClientId,
            ["iat"] = _now.ToUnixTimeSeconds(),
            ["exp"] = expiresAt.ToUnixTimeSeconds(),
            ["jti"] = jti,
            ["scope"] = string.Join(' ', _entry.Scope),
        };
        AddAuthenticationEvent(claims);

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

        return new PreparedPayload(new TokenPayload(claims), expiresAt);
    }

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
}

/// <summary>A finalized payload and the expiry it carries, so the response's <c>expires_in</c> cannot disagree with <c>exp</c>.</summary>
internal readonly record struct PreparedPayload(TokenPayload Payload, DateTimeOffset ExpiresAt);
