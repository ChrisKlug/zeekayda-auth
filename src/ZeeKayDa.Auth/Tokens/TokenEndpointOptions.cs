using ZeeKayDa.Auth.Configuration;

namespace ZeeKayDa.Auth.Tokens;

/// <summary>
/// Token endpoint configuration options.
/// </summary>
public sealed class TokenEndpointOptions
{
    private string? _uri;
    private ICollection<string>? _advertisedAuthMethods;
    private TimeSpan _refreshTokenLifetime = TimeSpan.FromDays(14);
    private TimeSpan _absoluteFamilyLifetime = TimeSpan.FromDays(90);
    private TimeSpan _accessTokenLifetime = TimeSpan.FromMinutes(10);
    private TimeSpan _idTokenLifetime = TimeSpan.FromMinutes(5);
    private bool _frozen;

    /// <summary>
    /// Gets or sets an explicit override for the <c>token_endpoint</c> URI published in the
    /// discovery document. When <see langword="null"/>, the value is derived from the issuer.
    /// </summary>
    public string? Uri
    {
        get => _uri;
        set => _uri = FrozenOptions.Assign(_frozen, value, "AuthorizationServerOptions.TokenEndpoint.Uri");
    }

    /// <summary>
    /// Gets or sets an optional narrowing filter on the client authentication methods the token
    /// endpoint advertises and accepts. <see langword="null"/> — the default — advertises every
    /// method a registered client authenticator performs, plus
    /// <see cref="TokenEndpointAuthMethods.None"/>.
    /// </summary>
    /// <remarks>
    /// <para>
    /// This filter can only withhold a method, never add one no authenticator performs; naming such a
    /// method warns at startup, and an empty filter fails startup.
    /// </para>
    /// <para>
    /// <see cref="TokenEndpointAuthMethods.None"/> is how public clients authenticate, so leaving it out
    /// refuses them.
    /// </para>
    /// <para>
    /// Maps to the <c>token_endpoint_auth_methods_supported</c> discovery metadata field.
    /// </para>
    /// </remarks>
    public ICollection<string>? AdvertisedAuthMethods
    {
        get => _advertisedAuthMethods;
        set => _advertisedAuthMethods = FrozenOptions.Assign(_frozen, value, "AuthorizationServerOptions.TokenEndpoint.AdvertisedAuthMethods");
    }

    /// <summary>
    /// Gets or sets the lifetime of issued refresh tokens. Defaults to 14 days.
    /// </summary>
    /// <remarks>
    /// Must be greater than <see cref="TimeSpan.Zero"/>. No upper bound is enforced; a longer lifetime widens
    /// the window in which a compromised token remains usable.
    /// </remarks>
    public TimeSpan RefreshTokenLifetime
    {
        get => _refreshTokenLifetime;
        set => _refreshTokenLifetime = FrozenOptions.Assign(_frozen, value, "AuthorizationServerOptions.TokenEndpoint.RefreshTokenLifetime");
    }

    /// <summary>
    /// Gets or sets the absolute wall-clock lifetime of a refresh token family, measured from the
    /// family's first token. Defaults to 90 days.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Set at family birth and kept through every rotation; each token's own expiry is clamped to
    /// <c>min(now + RefreshTokenLifetime, FamilyAbsoluteExpiry)</c>. Must be greater than
    /// <see cref="TimeSpan.Zero"/>.
    /// </para>
    /// <para>
    /// <see cref="TimeSpan.MaxValue"/> disables the cap, so families live as long as they are used. That
    /// grows a persisted grant store without bound, and warns at startup.
    /// </para>
    /// </remarks>
    public TimeSpan AbsoluteFamilyLifetime
    {
        get => _absoluteFamilyLifetime;
        set => _absoluteFamilyLifetime = FrozenOptions.Assign(_frozen, value, "AuthorizationServerOptions.TokenEndpoint.AbsoluteFamilyLifetime");
    }

    /// <summary>
    /// Gets or sets the server-wide lifetime of issued access tokens. Defaults to ten minutes.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Short by design. An access token is a self-contained JWT no code path checks against a store, so a
    /// resource server accepts it until it expires, however the grant behind it ended. This value, plus
    /// the resource server's clock-skew tolerance, is that window;
    /// <see href="https://www.rfc-editor.org/rfc/rfc7009#section-3">RFC 7009 §3</see> sanctions keeping
    /// self-contained tokens short-lived and renewing them.
    /// </para>
    /// <para>
    /// Renewal is a fresh authorization request
    /// (<see href="https://www.rfc-editor.org/rfc/rfc9700#section-4.14.2">RFC 9700 §4.14.2</see>). A browser
    /// still signed in is not asked to sign in again, but is asked for consent again unless the client has
    /// <see cref="Clients.IClient.RequireConsent"/> off. The refresh-token grant is not served, so listing
    /// <see cref="GrantType.RefreshToken"/> in <see cref="AuthorizationServerOptions.GrantTypesSupported"/>
    /// fails startup.
    /// </para>
    /// <para>
    /// A client may override it through <see cref="Clients.IClient.AccessTokenLifetime"/>. Must be greater
    /// than <see cref="TimeSpan.Zero"/>; a value past <see cref="AbsoluteFamilyLifetime"/> warns at startup.
    /// </para>
    /// </remarks>
    public TimeSpan AccessTokenLifetime
    {
        get => _accessTokenLifetime;
        set => _accessTokenLifetime = FrozenOptions.Assign(_frozen, value, "AuthorizationServerOptions.TokenEndpoint.AccessTokenLifetime");
    }

    /// <summary>
    /// Gets or sets the server-wide lifetime of issued ID tokens. Defaults to five minutes.
    /// </summary>
    /// <remarks>
    /// Short by design: an ID token is consumed once, on receipt. A client may override it through
    /// <see cref="Clients.IClient.IdTokenLifetime"/>. Must be greater than <see cref="TimeSpan.Zero"/>.
    /// </remarks>
    public TimeSpan IdTokenLifetime
    {
        get => _idTokenLifetime;
        set => _idTokenLifetime = FrozenOptions.Assign(_frozen, value, "AuthorizationServerOptions.TokenEndpoint.IdTokenLifetime");
    }

    /// <summary>
    /// Computes the <c>FamilyAbsoluteExpiry</c> for a family born at <paramref name="now"/>, mapping an
    /// overflow, such as the <see cref="TimeSpan.MaxValue"/> escape hatch, to <see cref="DateTimeOffset.MaxValue"/>.
    /// </summary>
    /// <param name="now">The current time, at family birth.</param>
    public DateTimeOffset ComputeFamilyAbsoluteExpiry(DateTimeOffset now)
    {
        return TokenLifetimes.ExpiresAt(now, AbsoluteFamilyLifetime);
    }

    /// <summary>Makes every collection read-only and refuses any later change.</summary>
    internal void Freeze()
    {
        if (_frozen)
            return;

        AdvertisedAuthMethods = FrozenOptions.Copy(AdvertisedAuthMethods);
        _frozen = true;
    }
}
