namespace ZeeKayDa.Auth.Tokens;

/// <summary>
/// Options for the development signing key provider registered by
/// <c>AddDevelopmentJwtSigningKeys()</c>.
/// </summary>
/// <remarks>
/// This options type is for development and testing only. In production, use a real key
/// provider backed by a KMS, HSM, or a securely stored key.
/// </remarks>
internal sealed class DevelopmentSigningKeyOptions : JwtSigningServiceOptions
{
    /// <summary>
    /// Initialises development options with an infinite refresh interval.
    /// </summary>
    /// <remarks>
    /// Dev keys are memoized for the entire process lifetime. Setting
    /// <see cref="JwtSigningServiceOptions.RefreshInterval"/> to <see cref="TimeSpan.MaxValue"/>
    /// prevents the base class from ever calling <c>LoadKeysAsync</c> a second time and
    /// disposing the key set that is still held by the memoization field, which would otherwise
    /// cause an <see cref="ObjectDisposedException"/> on the next signing call.
    /// </remarks>
    public DevelopmentSigningKeyOptions()
    {
        RefreshInterval = TimeSpan.MaxValue;
    }

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
    /// <c>AddDevelopmentJwtSigningKeys</c> is
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
}
