namespace ZeeKayDa.Auth.Tokens;

/// <summary>
/// Options for the development signing key provider that is actually registered and consumed
/// internally regardless of which registration method is used
/// (<c>AddInMemoryDevelopmentJwtSigningKeys()</c> or <c>AddPersistedDevelopmentJwtSigningKeys()</c>).
/// </summary>
/// <remarks>
/// For development and testing only — in production, use a real key provider backed by a KMS,
/// HSM, or a securely stored key. This is the <c>configure</c> callback type for
/// <c>AddPersistedDevelopmentJwtSigningKeys()</c>; <c>AddInMemoryDevelopmentJwtSigningKeys()</c>
/// uses the smaller <see cref="InMemoryDevelopmentSigningKeyOptions"/> instead, which has no
/// <see cref="PersistToDirectory"/> member, so an in-memory registration can never be silently
/// turned into a persisted one.
/// </remarks>
public sealed class DevelopmentSigningKeyOptions
{
    /// <summary>
    /// Gets or sets the name of the host environment in which the service is running.
    /// </summary>
    /// <remarks>
    /// Set automatically by the AspNetCore registration layer from
    /// <c>IHostEnvironment.EnvironmentName</c>. The setter is internal so the value read by
    /// <see cref="DevelopmentSigningKeyGate"/> cannot be spoofed through the public
    /// <c>configure</c> callback. When <see langword="null"/> (unit-test scenario with no host),
    /// the environment gate is skipped.
    /// </remarks>
    public string? EnvironmentName { get; internal set; }

    /// <summary>
    /// Gets or sets the path to the directory where the development signing key is persisted.
    /// </summary>
    /// <remarks>
    /// <para>
    /// When <see langword="null"/> (the default), a fresh RSA key is generated in memory on each
    /// startup and never written to disk — tokens issued in a previous session will not validate
    /// after a restart. When set, the key is written to (or loaded from)
    /// <c>{PersistToDirectory}/dev-signing-key.pem</c> with restrictive permissions
    /// (<c>0700</c>/<c>0600</c> on Unix). The default path when <c>persistTo: null</c> is passed
    /// to <c>AddPersistedDevelopmentJwtSigningKeys</c> is
    /// <c>{IHostEnvironment.ContentRootPath}/.zeekayda/signing-keys/</c>.
    /// </para>
    /// <para>
    /// This value is developer-supplied configuration set at application startup, never bound
    /// from runtime user input, so an absolute path is accepted intentionally. Key confidentiality
    /// is enforced by <see cref="IDevelopmentSigningKeyFileSystem"/> regardless of the path shape.
    /// </para>
    /// </remarks>
    public string? PersistToDirectory { get; set; }

    /// <summary>
    /// Gets or sets the list of host environment names in which this development signing key
    /// provider is permitted to run. Defaults to <c>["Development"]</c>.
    /// </summary>
    /// <remarks>
    /// <para>
    /// When the host environment is not in this list, startup fails with a
    /// <see cref="ZeeKayDaConfigurationException"/> so an accidental development-key
    /// configuration is never silently deployed to a non-permitted host. <c>Production</c> can
    /// never be added to this list — the gate rejects it unconditionally, enforced both by
    /// <see cref="AllowedDevEnvironmentsValidator"/> at startup and again by
    /// <see cref="DevelopmentSigningKeyGate"/> itself.
    /// </para>
    /// <para>
    /// Callers may widen the default <c>["Development"]</c> list — e.g.
    /// <c>["Development", "IntegrationTesting", "CI"]</c> — for test hosts that intentionally run
    /// under a non-Development environment name. A
    /// <see cref="Microsoft.Extensions.Logging.LogLevel.Critical"/> entry is emitted on every
    /// startup where the host environment is in the list but is not <c>"Development"</c>.
    /// </para>
    /// <para>
    /// This list MUST NOT be sourced from <c>appsettings.json</c> or any file that may be
    /// committed to source control — a config-file misconfiguration could otherwise silently
    /// widen the allowed environments in production. Set it explicitly in code instead.
    /// </para>
    /// </remarks>
    public IReadOnlyList<string> AllowedDevelopmentJwtSigningKeysEnvironments { get; set; } =
        ["Development"];
}
