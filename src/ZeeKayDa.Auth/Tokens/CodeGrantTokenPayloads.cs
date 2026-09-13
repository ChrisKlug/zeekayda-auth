using ZeeKayDa.Auth.Clients;
using ZeeKayDa.Auth.Stores;

namespace ZeeKayDa.Auth.Tokens;

/// <summary>
/// The protocol claims of the tokens an authorization code becomes. Every value comes from the
/// grant — the redeemed entry, the issuer, the client — never from the request that redeemed it.
/// </summary>
internal static class CodeGrantTokenPayloads
{
    /// <summary>
    /// The access token's claims (RFC 9068 §2.2): the issuer is its audience, since <c>openid</c>
    /// is always granted and userinfo is a resource the issuer hosts.
    /// </summary>
    public static TokenPayload AccessToken(
        string issuer,
        IClientMetadata client,
        AuthorizationCodeEntry entry,
        DateTimeOffset now,
        DateTimeOffset expiresAt,
        string jti)
    {
        ArgumentException.ThrowIfNullOrEmpty(issuer);
        ArgumentNullException.ThrowIfNull(client);
        ArgumentNullException.ThrowIfNull(entry);
        ArgumentException.ThrowIfNullOrEmpty(jti);

        var claims = new Dictionary<string, object?>(StringComparer.Ordinal)
        {
            ["iss"] = issuer,
            ["sub"] = entry.Sub,
            ["aud"] = issuer,
            ["client_id"] = client.ClientId,
            ["iat"] = now.ToUnixTimeSeconds(),
            ["exp"] = expiresAt.ToUnixTimeSeconds(),
            ["jti"] = jti,
            ["scope"] = string.Join(" ", entry.Scope),
        };
        AddAuthenticationEvent(claims, entry);

        return new TokenPayload(claims);
    }

    /// <summary>
    /// The ID token's claims (OIDC Core §2): one audience, the requesting client, and the
    /// request's <c>nonce</c> whenever it carried one.
    /// </summary>
    public static TokenPayload IdToken(
        string issuer,
        IClientMetadata client,
        AuthorizationCodeEntry entry,
        DateTimeOffset now,
        DateTimeOffset expiresAt)
    {
        ArgumentException.ThrowIfNullOrEmpty(issuer);
        ArgumentNullException.ThrowIfNull(client);
        ArgumentNullException.ThrowIfNull(entry);

        var claims = new Dictionary<string, object?>(StringComparer.Ordinal)
        {
            ["iss"] = issuer,
            ["sub"] = entry.Sub,
            ["aud"] = client.ClientId,
            ["iat"] = now.ToUnixTimeSeconds(),
            ["exp"] = expiresAt.ToUnixTimeSeconds(),
        };
        AddAuthenticationEvent(claims, entry);

        if (entry.Nonce is { } nonce)
            claims["nonce"] = nonce;

        return new TokenPayload(claims);
    }

    /// <summary>
    /// The original authentication event, on both tokens (RFC 9068 §2.2.1): <c>auth_time</c>
    /// always, <c>acr</c> and <c>amr</c> when the grant carries them and never as <c>null</c>.
    /// </summary>
    private static void AddAuthenticationEvent(Dictionary<string, object?> claims, AuthorizationCodeEntry entry)
    {
        claims["auth_time"] = entry.AuthTime.ToUnixTimeSeconds();

        if (entry.Acr is { } acr)
            claims["acr"] = acr;

        if (entry.Amr is { Count: > 0 } amr)
            claims["amr"] = amr.ToArray();
    }
}
