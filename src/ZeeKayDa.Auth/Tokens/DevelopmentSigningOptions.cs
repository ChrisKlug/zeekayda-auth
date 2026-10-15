namespace ZeeKayDa.Auth.Tokens;

/// <summary>
/// Options for the development signing key, set through the <c>configure</c> callback of
/// <c>AddInMemoryDevelopmentSigning()</c> or <c>AddPersistedDevelopmentSigning()</c>.
/// </summary>
/// <remarks>
/// For development and testing only; in production, use a real key provider backed by a KMS, HSM,
/// or a securely stored key.
/// </remarks>
public sealed class DevelopmentSigningOptions
{
    /// <summary>
    /// Gets or sets the host environment names in which the development signing key may run.
    /// Defaults to <c>["Development"]</c>.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Outside these environments startup fails, so a development key is never silently deployed.
    /// <c>Production</c> can never be listed, and a listed environment other than <c>Development</c> logs a
    /// <see cref="Microsoft.Extensions.Logging.LogLevel.Critical"/> entry on every start.
    /// </para>
    /// <para>
    /// Set it in code, never from a configuration file that could widen the list in production.
    /// </para>
    /// </remarks>
    /// <exception cref="ArgumentNullException">Thrown when set to <see langword="null"/>.</exception>
    public IReadOnlyList<string> AllowedEnvironments
    {
        get;
        // Copied, so a caller keeping the list it assigned cannot change the gate after validation.
        set => field = [.. value ?? throw new ArgumentNullException(nameof(value))];
    } = ["Development"];

    // Set by the registration from IHostEnvironment. Internal so the configure callback cannot
    // spoof the value the gate reads.
    internal string? EnvironmentName { get; set; }

    // The persisted key's directory, null for in-memory; set only from AddPersistedDevelopmentSigning.
    // Any path is accepted: confidentiality is enforced by IDevelopmentSigningKeyFileSystem.
    internal string? PersistToDirectory { get; set; }
}
