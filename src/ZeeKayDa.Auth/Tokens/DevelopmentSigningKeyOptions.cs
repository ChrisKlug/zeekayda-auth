namespace ZeeKayDa.Auth.Tokens;

/// <summary>
/// Options for the development signing key provider that is actually registered and consumed
/// internally regardless of which registration method is used
/// (<c>AddInMemoryDevelopmentJwtSigningKeys()</c> or <c>AddPersistedDevelopmentJwtSigningKeys()</c>).
/// </summary>
/// <remarks>
/// <para>
/// This options type is for development and testing only. In production, use a real key
/// provider backed by a KMS, HSM, or a securely stored key.
/// </para>
/// <para>
/// This is also the public <c>configure</c> callback type for
/// <c>AddPersistedDevelopmentJwtSigningKeys()</c>, since persistence configuration
/// (<see cref="PersistToDirectory"/>) is meaningful for that method. It is deliberately
/// <strong>not</strong> the callback type for <c>AddInMemoryDevelopmentJwtSigningKeys()</c> — that
/// method uses the smaller <see cref="InMemoryDevelopmentSigningKeyOptions"/> instead, which has no
/// <see cref="PersistToDirectory"/> member, so that an in-memory registration can never be silently
/// turned into a persisted one through its configure callback.
/// </para>
/// </remarks>
public sealed class DevelopmentSigningKeyOptions : JwtSigningServiceOptions
{
    /// <summary>
    /// Initialises development options in static-source mode.
    /// </summary>
    /// <remarks>
    /// Dev keys are memoized for the entire process lifetime. Setting
    /// <see cref="JwtSigningServiceOptions.KeySourceRefreshInterval"/> to <see langword="null"/>
    /// prevents the base class from ever calling <c>LoadKeysAsync</c> a second time and
    /// disposing the key set that is still held by the memoization field, which would otherwise
    /// cause an <see cref="ObjectDisposedException"/> on the next signing call.
    /// </remarks>
    public DevelopmentSigningKeyOptions()
    {
        // Static-source mode: dev keys never change for the life of the process (see remarks).
        KeySourceRefreshInterval = null;
    }

    /// <summary>
    /// Gets or sets the name of the host environment in which the service is running.
    /// </summary>
    /// <remarks>
    /// Set automatically by the AspNetCore registration layer from <c>IHostEnvironment.EnvironmentName</c>.
    /// It is never meant to be caller-set — the setter is internal so that the value read by the
    /// environment gate (<see cref="DevelopmentSigningKeyGate"/>) cannot be spoofed through the
    /// public <c>configure</c> callback. When <see langword="null"/> (the default, unit-test
    /// scenario with no host), the environment gate is intentionally skipped.
    /// </remarks>
    public string? EnvironmentName { get; internal set; }

    /// <summary>
    /// Gets or sets the path to the directory where the development signing key is persisted.
    /// </summary>
    /// <remarks>
    /// <para>
    /// When <see langword="null"/> (the default), a fresh RSA key is generated in memory on
    /// each startup and is never written to disk. Tokens issued in a previous session will
    /// not validate after a restart.
    /// </para>
    /// <para>
    /// When set to a non-null path, the key is written to (or loaded from)
    /// <c>{PersistToDirectory}/dev-signing-key.pem</c>. The directory and file are created
    /// with restrictive permissions (<c>0700</c>/<c>0600</c> on Unix) so that no other local
    /// user can read the key file.
    /// </para>
    /// <para>
    /// The default path when <c>persistTo: null</c> is passed to
    /// <c>AddPersistedDevelopmentJwtSigningKeys</c> is
    /// <c>{IHostEnvironment.ContentRootPath}/.zeekayda/signing-keys/</c>.
    /// </para>
    /// <para>
    /// <b>Trust decision:</b> This value is developer-supplied configuration set at application
    /// startup — it is never bound from runtime user input, URL parameters, or any untrusted
    /// source. Absolute paths are therefore accepted intentionally: a developer configuring their
    /// own machine chooses where keys are stored. Key confidentiality is enforced by
    /// <see cref="IDevelopmentSigningKeyFileSystem"/> regardless of the path shape; the directory is created
    /// with owner-only permissions (<c>0700</c>) and the key file with <c>0600</c>, and both are
    /// validated for correct permissions and ownership before use.
    /// </para>
    /// </remarks>
    public string? PersistToDirectory { get; set; }

    /// <summary>
    /// Gets or sets the list of host environment names in which this development signing key
    /// provider is permitted to run. Defaults to <c>["Development"]</c>.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Development signing keys are ephemeral or stored in a local file and are not suitable
    /// for production. When the host environment is not in this list, startup fails with a
    /// <see cref="ZeeKayDaConfigurationException"/> so that an accidental development-key
    /// configuration is never silently deployed to a non-permitted host. This is a
    /// provider-scoped, code-only opt-in — set only through the registration method's
    /// <c>configure</c> callback, never bound from configuration — not a server-wide setting,
    /// because it is inert unless a development-key registration method is actually in use.
    /// </para>
    /// <para>
    /// <c>Production</c> can never be added to this list: the gate rejects a <c>Production</c>
    /// host environment unconditionally, regardless of the list's contents. This is enforced
    /// both at startup validation time (<see cref="AllowedDevEnvironmentsValidator"/>) and again
    /// by <see cref="DevelopmentSigningKeyGate"/> itself, so it cannot be bypassed by
    /// misconfiguration.
    /// </para>
    /// <para>
    /// The default list contains only <c>"Development"</c>. Callers may widen this list to
    /// include additional environment names — for example,
    /// <c>["Development", "IntegrationTesting", "CI"]</c> — for test hosts that intentionally
    /// run under a non-Development environment name. A
    /// <see cref="Microsoft.Extensions.Logging.LogLevel.Critical"/> entry is emitted on every
    /// startup while the host environment is in the list but is not <c>"Development"</c>,
    /// because an ephemeral or non-rotating signing key in such an environment breaks signature
    /// validation for every relying party on restart.
    /// </para>
    /// <para>
    /// This list MUST NOT be sourced from <c>appsettings.json</c> or any other file that may
    /// be committed to source control. Set it explicitly in code or via an environment variable.
    /// Sourcing from configuration defeats the purpose of the gate because a misconfiguration
    /// in a config file could silently widen the allowed environments in production.
    /// </para>
    /// </remarks>
    public IReadOnlyList<string> AllowedDevelopmentJwtSigningKeysEnvironments { get; set; } =
        ["Development"];
}
