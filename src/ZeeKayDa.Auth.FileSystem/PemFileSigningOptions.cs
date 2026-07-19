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
    /// Gets or sets the path to a separate private-key PEM file for <see cref="Path"/>, set by the
    /// <c>AddPemFileSigning(builder, certPath, keyPath, algorithm, configure)</c> overload. When
    /// <see langword="null"/> (the default), <see cref="Path"/> is a combined cert+key file, exactly
    /// as this provider has always required (issue #405).
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
    /// Gets every additional PEM file registered via <see cref="AddFile(string)"/> or
    /// <see cref="AddFile(string, string)"/>, in registration order.
    /// </summary>
    public IReadOnlyList<PemFileRegistration> AdditionalFiles => _additionalFiles;

    /// <summary>
    /// Registers an additional combined cert+key PEM file to support rotation with overlapping
    /// validity windows (ADR 0011 §3.5; issue #282's multi-key registration shape).
    /// </summary>
    /// <param name="path">The additional combined cert+key PEM file's path.</param>
    /// <returns>This instance, so calls can be chained.</returns>
    public PemFileSigningOptions AddFile(string path)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        _additionalFiles.Add(new PemFileRegistration(path, null));
        return this;
    }

    /// <summary>
    /// Registers an additional PEM file, with its certificate and private key stored in separate
    /// files, to support rotation with overlapping validity windows (ADR 0011 §3.5; issue #282's
    /// multi-key registration shape; issue #405's separate cert/key file support).
    /// </summary>
    /// <param name="certPath">The additional certificate-only PEM file's path.</param>
    /// <param name="keyPath">The additional private-key-only PEM file's path.</param>
    /// <returns>This instance, so calls can be chained.</returns>
    public PemFileSigningOptions AddFile(string certPath, string keyPath)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(certPath);
        ArgumentException.ThrowIfNullOrWhiteSpace(keyPath);
        _additionalFiles.Add(new PemFileRegistration(certPath, keyPath));
        return this;
    }
}

/// <summary>
/// One additional PEM file registered via <see cref="PemFileSigningOptions.AddFile(string)"/> or
/// <see cref="PemFileSigningOptions.AddFile(string, string)"/>.
/// </summary>
/// <param name="Path">The certificate path — a combined cert+key file when <paramref name="KeyPath"/> is <see langword="null"/>, otherwise the certificate-only file.</param>
/// <param name="KeyPath">The separate private-key file's path, or <see langword="null"/> for a combined cert+key file.</param>
public sealed record PemFileRegistration(string Path, string? KeyPath = null);
