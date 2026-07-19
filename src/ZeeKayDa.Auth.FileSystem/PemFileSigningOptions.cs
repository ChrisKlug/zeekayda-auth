using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.FileSystem;

/// <summary>
/// Configuration options for <c>AddPemFileSigning</c>.
/// </summary>
/// <remarks>
/// <see cref="JwtSigningServiceOptions.KeySourceRefreshInterval"/> is inherited from the base class and
/// defaults to 5 minutes. Unlike the Azure Key Vault providers, this value does not gate a
/// re-download of private key material — every registered file is re-read from disk on every
/// refresh, which has no external cost. Instead it doubles as the threshold used to warn when a
/// rotated-in file's <see cref="System.Security.Cryptography.X509Certificates.X509Certificate2.NotBefore"/>
/// is scheduled too soon relative to how often relying parties are expected to have polled the
/// JWKS (ADR 0011 §3.5; see <see cref="SigningKeyRotation.HasTooSoonPendingActivation"/>).
/// </remarks>
public sealed class PemFileSigningOptions : JwtSigningServiceOptions
{
    private readonly List<PemFileRegistration> _additionalFiles = [];

    /// <summary>
    /// Gets or sets the path to the required/primary PEM file. When <see cref="KeyPath"/> is
    /// <see langword="null"/>, this file must contain both the certificate and its private key (a
    /// single combined cert+key PEM file). Set by <c>AddPemFileSigning</c>.
    /// </summary>
    public string Path { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets the path to a separate private-key PEM file for <see cref="Path"/>, set by
    /// <c>AddPemFileSigning</c>'s <c>keyPath</c> parameter. When <see langword="null"/> (the
    /// default), <see cref="Path"/> is a combined cert+key file, exactly as this provider has
    /// always required (issue #405).
    /// </summary>
    public string? KeyPath { get; set; }

    /// <summary>
    /// Gets or sets the JWS algorithm to use when signing. A certificate's key does not itself
    /// declare RS256 vs PS256 — that choice is made here and must match the certificate's actual
    /// key type (RSA algorithms for RSA certificates, EC algorithms for EC certificates). Defaults
    /// to RS256.
    /// </summary>
    public SigningAlgorithm Algorithm { get; set; } = SigningAlgorithm.RS256;

    /// <summary>
    /// Gets every additional PEM file registered via <see cref="AddFile(string, string)"/>, in
    /// registration order.
    /// </summary>
    public IReadOnlyList<PemFileRegistration> AdditionalFiles => _additionalFiles;

    /// <summary>
    /// Registers an additional PEM file to support rotation with overlapping validity windows
    /// (ADR 0011 §3.5; issue #282's multi-key registration shape). When <paramref name="keyPath"/>
    /// is <see langword="null"/> (the default), <paramref name="path"/> must be a combined cert+key
    /// file; when supplied, <paramref name="path"/> is a certificate-only file and
    /// <paramref name="keyPath"/> is a separate private-key-only file (issue #405).
    /// </summary>
    /// <param name="path">
    /// The additional PEM file's path — a combined cert+key file when <paramref name="keyPath"/> is
    /// <see langword="null"/>, otherwise the certificate-only file.
    /// </param>
    /// <param name="keyPath">
    /// The additional private-key-only PEM file's path, or <see langword="null"/> (the default) when
    /// <paramref name="path"/> is a combined cert+key file.
    /// </param>
    /// <returns>This instance, so calls can be chained.</returns>
    public PemFileSigningOptions AddFile(string path, string? keyPath = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);

        if (keyPath is not null)
            ArgumentException.ThrowIfNullOrWhiteSpace(keyPath);

        _additionalFiles.Add(new PemFileRegistration(path, keyPath));
        return this;
    }
}

/// <summary>
/// One additional PEM file registered via <see cref="PemFileSigningOptions.AddFile(string, string)"/>.
/// </summary>
/// <param name="Path">The certificate path — a combined cert+key file when <paramref name="KeyPath"/> is <see langword="null"/>, otherwise the certificate-only file.</param>
/// <param name="KeyPath">The separate private-key file's path, or <see langword="null"/> for a combined cert+key file.</param>
public sealed record PemFileRegistration(string Path, string? KeyPath = null);
