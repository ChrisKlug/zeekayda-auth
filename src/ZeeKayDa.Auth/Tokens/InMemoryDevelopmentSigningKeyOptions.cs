namespace ZeeKayDa.Auth.Tokens;

/// <summary>
/// Options for the ephemeral, in-memory development signing key provider registered by
/// <c>AddInMemoryDevelopmentJwtSigningKeys()</c>.
/// </summary>
/// <remarks>
/// <para>
/// This type is intentionally a separate, smaller type from <see cref="DevelopmentSigningKeyOptions"/>
/// rather than reusing it as the public configure surface. <see cref="DevelopmentSigningKeyOptions"/>
/// carries <see cref="DevelopmentSigningKeyOptions.PersistToDirectory"/>, which controls whether the
/// signing key is written to disk. If <c>AddInMemoryDevelopmentJwtSigningKeys()</c> exposed that same
/// type through its <c>configure</c> callback, a caller could set
/// <c>PersistToDirectory</c> from inside the "in-memory" registration method and silently get a
/// persisted key — defeating the entire point of naming the two registration methods differently.
/// This type has no <c>PersistToDirectory</c> member at all, so that mistake cannot compile.
/// </para>
/// <para>
/// Values set through this type are copied onto the real, internally-registered
/// <see cref="DevelopmentSigningKeyOptions"/> instance that the signing pipeline actually consumes;
/// see <c>ZeeKayDaAuthBuilderSigningExtensions.AddInMemoryDevelopmentJwtSigningKeys</c>.
/// </para>
/// </remarks>
public sealed class InMemoryDevelopmentSigningKeyOptions
{
    /// <summary>
    /// Gets or sets the list of host environment names in which this development signing key
    /// provider is permitted to run. Defaults to <c>["Development"]</c>.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Development signing keys are ephemeral and are not suitable for production. When the host
    /// environment is not in this list, startup fails with a
    /// <see cref="ZeeKayDaConfigurationException"/> so that an accidental development-key
    /// configuration is never silently deployed to a non-permitted host. This is a
    /// provider-scoped, code-only opt-in — set only through this <c>configure</c> callback, never
    /// bound from configuration.
    /// </para>
    /// <para>
    /// <c>Production</c> can never be added to this list: the gate rejects a <c>Production</c>
    /// host environment unconditionally, regardless of the list's contents.
    /// </para>
    /// <para>
    /// The default list contains only <c>"Development"</c>. Callers may widen this list to
    /// include additional environment names — for example,
    /// <c>["Development", "IntegrationTesting", "CI"]</c> — for test hosts that intentionally
    /// run under a non-Development environment name.
    /// </para>
    /// <para>
    /// This list MUST NOT be sourced from <c>appsettings.json</c> or any other file that may
    /// be committed to source control. Set it explicitly in code or via an environment variable.
    /// </para>
    /// </remarks>
    public IReadOnlyList<string> AllowedDevelopmentJwtSigningKeysEnvironments { get; set; } =
        ["Development"];
}
