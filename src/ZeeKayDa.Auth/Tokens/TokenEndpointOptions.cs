namespace ZeeKayDa.Auth.Tokens;

/// <summary>
/// Token endpoint configuration options.
/// </summary>
public sealed class TokenEndpointOptions
{
    /// <summary>
    /// Gets or sets an explicit override for the <c>token_endpoint</c> URI published in the
    /// discovery document. When <see langword="null"/>, the value is derived from the issuer.
    /// </summary>
    public string? Uri { get; set; }

    /// <summary>
    /// Gets or sets the client authentication methods supported by the token endpoint.
    /// Defaults to <c>["client_secret_basic"]</c> (see <see cref="TokenEndpointAuthMethods.ClientSecretBasic"/>).
    /// </summary>
    /// <remarks>
    /// <para>
    /// Maps to the <c>token_endpoint_auth_methods_supported</c> discovery metadata field.
    /// Must not be null or empty and must contain at least one non-<c>"none"</c> method
    /// (see <see cref="TokenEndpointAuthMethods.None"/>) if
    /// <see cref="AuthorizationServerOptions.GrantTypesSupported"/> includes
    /// <see cref="GrantType.ClientCredentials"/>.
    /// </para>
    /// <para>
    /// Well-known values are available as constants on <see cref="TokenEndpointAuthMethods"/>.
    /// Custom authentication methods (e.g. <c>tls_client_auth</c>) can be expressed as plain
    /// strings alongside those constants.
    /// </para>
    /// </remarks>
    public ICollection<string> AuthMethodsSupported { get; set; } =
        [TokenEndpointAuthMethods.ClientSecretBasic];

    /// <summary>
    /// Gets or sets the lifetime of issued refresh tokens.
    /// Defaults to 14 days.
    /// </summary>
    /// <remarks>
    /// Must be greater than <see cref="TimeSpan.Zero"/>; rejected at startup otherwise. No upper
    /// bound is enforced — a longer lifetime increases the window in which an undetected family
    /// revocation gap or a compromised token remains exploitable, so stricter deployments should
    /// dial this down.
    /// </remarks>
    public TimeSpan RefreshTokenLifetime { get; set; } = TimeSpan.FromDays(14);

    /// <summary>
    /// Gets or sets the absolute wall-clock lifetime of a refresh token family, measured from the
    /// family's first token. Defaults to 90 days.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Baked into <c>FamilyAbsoluteExpiry</c> at family birth and propagated verbatim through
    /// every rotation, so the whole chain shares one absolute ceiling. Each token's own expiry is
    /// clamped to <c>min(now + RefreshTokenLifetime, FamilyAbsoluteExpiry)</c> —
    /// <see cref="RefreshTokenLifetime"/> is the per-token idle window; this option is the
    /// whole-family hard cap. Must be greater than <see cref="TimeSpan.Zero"/>; rejected at
    /// startup otherwise.
    /// </para>
    /// <para>
    /// <strong>Escape hatch.</strong> Setting this to <see cref="TimeSpan.MaxValue"/> disables the
    /// absolute cap: families then live indefinitely, bounded only by
    /// <see cref="RefreshTokenLifetime"/> idle expiry. This causes unbounded row growth in a
    /// persisted grant store, so the framework emits a startup warning whenever this sentinel is
    /// configured.
    /// </para>
    /// </remarks>
    public TimeSpan AbsoluteFamilyLifetime { get; set; } = TimeSpan.FromDays(90);

    /// <summary>
    /// Computes the <c>FamilyAbsoluteExpiry</c> to bake into a refresh token family at birth, from
    /// <paramref name="now"/> and this instance's <see cref="AbsoluteFamilyLifetime"/>.
    /// </summary>
    /// <param name="now">The current time, at family birth.</param>
    /// <remarks>
    /// Sentinel-safe: a naive <c>now + AbsoluteFamilyLifetime</c> would overflow when
    /// <see cref="AbsoluteFamilyLifetime"/> is the <see cref="TimeSpan.MaxValue"/> escape hatch.
    /// This method maps that sentinel (and any other overflowing addition) to
    /// <see cref="DateTimeOffset.MaxValue"/> instead.
    /// </remarks>
    public DateTimeOffset ComputeFamilyAbsoluteExpiry(DateTimeOffset now)
    {
        if (AbsoluteFamilyLifetime == TimeSpan.MaxValue)
            return DateTimeOffset.MaxValue;

        try
        {
            return now + AbsoluteFamilyLifetime;
        }
        catch (ArgumentOutOfRangeException)
        {
            return DateTimeOffset.MaxValue;
        }
    }
}
