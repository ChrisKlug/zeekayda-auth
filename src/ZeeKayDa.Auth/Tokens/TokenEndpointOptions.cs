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
    /// <para>
    /// Must be greater than <see cref="TimeSpan.Zero"/>. Values at or below zero are rejected
    /// at startup by <c>AuthorizationServerOptionsValidator</c>.
    /// </para>
    /// <para>
    /// No upper bound is enforced; operators are responsible for choosing a value appropriate
    /// to their threat model. Long-lived integration scenarios may require values of weeks or
    /// months; stricter deployments should dial this down to hours or days. A longer lifetime
    /// increases the window in which an undetected family revocation gap or a compromised token
    /// remains exploitable.
    /// </para>
    /// </remarks>
    public TimeSpan RefreshTokenLifetime { get; set; } = TimeSpan.FromDays(14);

    /// <summary>
    /// Gets or sets the absolute wall-clock lifetime of a refresh token family, measured from the
    /// family's first token. Defaults to 90 days.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Baked into <c>FamilyAbsoluteExpiry</c> at family birth (<c>now + AbsoluteFamilyLifetime</c>)
    /// and propagated verbatim through every rotation in the family, so the whole chain shares one
    /// absolute ceiling (ADR 0014 §5). Each token's own expiry is clamped to
    /// <c>min(now + RefreshTokenLifetime, FamilyAbsoluteExpiry)</c> — <see cref="RefreshTokenLifetime"/>
    /// is the per-token idle window; this option is the whole-family hard cap. There is no
    /// separate idle-timeout option.
    /// </para>
    /// <para>
    /// Must be greater than <see cref="TimeSpan.Zero"/>. Values at or below zero are rejected at
    /// startup by <c>AuthorizationServerOptionsValidator</c>.
    /// </para>
    /// <para>
    /// <strong>Escape hatch.</strong> Setting this to <see cref="TimeSpan.MaxValue"/> — the
    /// <see cref="DateTimeOffset.MaxValue"/>-equivalent sentinel for a duration-typed option —
    /// disables the absolute cap: refresh token families then live indefinitely, bounded only by
    /// <see cref="RefreshTokenLifetime"/> idle expiry. This causes unbounded row growth in a
    /// persisted grant store (a resource concern, not a fail-open one) and is a warned, explicit
    /// opt-in: the framework emits a startup warning whenever this sentinel is configured, so an
    /// unbounded family lifetime is never a silent accident.
    /// </para>
    /// </remarks>
    public TimeSpan AbsoluteFamilyLifetime { get; set; } = TimeSpan.FromDays(90);
}
