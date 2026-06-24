namespace ZeeKayDa.Auth.Tokens;

/// <summary>
/// Options for the development signing key provider registered by
/// <c>AddDevelopmentJwtSigningKeys()</c>.
/// </summary>
/// <remarks>
/// This options type is for development and testing only. In production, use a real key
/// provider backed by a KMS, HSM, or a securely stored key.
/// </remarks>
public sealed class DevelopmentSigningKeyOptions : JwtSigningServiceOptions
{
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
    /// </remarks>
    public string? PersistToDirectory { get; set; }
}
