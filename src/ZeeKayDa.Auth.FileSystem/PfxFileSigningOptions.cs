using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.FileSystem;

/// <summary>
/// Configuration options for <c>AddPfxFileSigning</c>.
/// </summary>
/// <remarks>
/// <para>
/// ADR 0015 Tier A (<see cref="KeySetOptions"/>, issue #423): the complete set of registered PFX
/// files is fixed at configuration time, and the only thing that ever advances is the wall clock
/// crossing each file's certificate <c>NotBefore</c>/<c>NotAfter</c> — mapped onto each key's
/// <see cref="ZeeKayDa.Auth.Tokens.KeyListing.ActivateAt"/>/<see cref="ZeeKayDa.Auth.Tokens.KeyListing.ExpiresAt"/>.
/// <see cref="KeySetOptions.PublicationLead"/> is inherited from <see cref="KeySetOptions"/> — see
/// that type's remarks for what it governs (an advisory too-soon-activation startup warning, not a
/// re-download cadence — there is nothing to re-download on this tier). This applies identically to
/// PFX, since <see cref="AdditionalFiles"/> supports the same pre-staged successor-certificate
/// rotation pattern PEM does.
/// </para>
/// <para>
/// Picking up a rotated-in or replaced file requires a process restart: this provider's
/// <c>ListKeysAsync</c> runs exactly once, ever, for the lifetime of a service instance (ADR 0015
/// §1/§4) — register the successor file via <see cref="AddFile"/> ahead of its intended activation
/// time and redeploy, rather than expecting a live reload.
/// </para>
/// <para>
/// <strong>Why <see cref="PasswordSource"/> is <c>Func&lt;CancellationToken, ValueTask&lt;string&gt;&gt;</c>.</strong>
/// A raw <c>string</c> password parameter would put a secret inline in application configuration,
/// which conflicts with this library's pattern of keeping key material and secrets out of plain
/// sight (issue #291's open design question). The delegate shape is async and cancellable so a
/// password can be sourced from an environment variable, a secret file, or a remote secret store
/// (Key Vault, etc.) without blocking a thread. It deliberately does not take an
/// <see cref="IServiceProvider"/>: that would tie every caller to DI-resolution machinery for what is
/// usually a simple lookup, and would complicate testing to no benefit. If a future DI-aware overload
/// is needed, it can be added as an additive, non-breaking overload — this shape does not foreclose
/// that.
/// </para>
/// </remarks>
public sealed class PfxFileSigningOptions : KeySetOptions
{
    private readonly List<(string Path, Func<CancellationToken, ValueTask<string>> PasswordSource)> _additionalFiles = [];

    /// <summary>
    /// Gets or sets the path to the required/primary PFX/PKCS#12 file. Set by
    /// <c>AddPfxFileSigning</c>.
    /// </summary>
    public string Path { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets the delegate that supplies the password for <see cref="Path"/>. Invoked once when
    /// the provider builds its one-time key listing (to open the bundle for its public certificate)
    /// and again only if <see cref="Path"/> is the active signer (to read the private key) —
    /// implementations that source the password from a slow or remote location should cache it
    /// themselves if repeated retrieval is undesirable. Set by <c>AddPfxFileSigning</c>.
    /// </summary>
    public Func<CancellationToken, ValueTask<string>>? PasswordSource { get; set; }

    /// <summary>
    /// Gets or sets the JWS algorithm to use when signing. A certificate's key does not itself
    /// declare RS256 vs PS256 — that choice is made here and must match the certificate's actual
    /// key type (RSA algorithms for RSA certificates, EC algorithms for EC certificates). Defaults
    /// to RS256.
    /// </summary>
    public SigningAlgorithm Algorithm { get; set; } = SigningAlgorithm.RS256;

    /// <summary>
    /// Gets the additional PFX files (and their password sources) registered via
    /// <see cref="AddFile"/>, in registration order.
    /// </summary>
    public IReadOnlyList<(string Path, Func<CancellationToken, ValueTask<string>> PasswordSource)> AdditionalFiles => _additionalFiles;

    /// <summary>
    /// Registers an additional PFX/PKCS#12 file to support rotation with overlapping validity
    /// windows (ADR 0015 §1; issue #282's multi-key registration shape). Each file may have its
    /// own password, since real-world PFX bundles are frequently password-per-file.
    /// </summary>
    /// <param name="path">The additional PFX file's path.</param>
    /// <param name="passwordSource">The delegate that supplies this file's password.</param>
    /// <returns>This instance, so calls can be chained.</returns>
    public PfxFileSigningOptions AddFile(string path, Func<CancellationToken, ValueTask<string>> passwordSource)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        ArgumentNullException.ThrowIfNull(passwordSource);
        _additionalFiles.Add((path, passwordSource));
        return this;
    }
}
