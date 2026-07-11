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
    private readonly List<string> _additionalPaths = [];

    /// <summary>
    /// Gets or sets the path to the required/primary PEM file. The file must contain both the
    /// certificate and its private key (a single combined cert+key PEM file). Set by
    /// <c>AddPemFileSigning</c>.
    /// </summary>
    public string Path { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets the JWS algorithm to use when signing. A certificate's key does not itself
    /// declare RS256 vs PS256 — that choice is made here and must match the certificate's actual
    /// key type (RSA algorithms for RSA certificates, EC algorithms for EC certificates). Defaults
    /// to RS256.
    /// </summary>
    public SigningAlgorithm Algorithm { get; set; } = SigningAlgorithm.RS256;

    /// <summary>
    /// Gets the paths of every additional PEM file registered via <see cref="AddFile"/>, in
    /// registration order.
    /// </summary>
    public IReadOnlyList<string> AdditionalPaths => _additionalPaths;

    /// <summary>
    /// Registers an additional combined cert+key PEM file to support rotation with overlapping
    /// validity windows (ADR 0011 §3.5; issue #282's multi-key registration shape).
    /// </summary>
    /// <param name="path">The additional PEM file's path.</param>
    /// <returns>This instance, so calls can be chained.</returns>
    public PemFileSigningOptions AddFile(string path)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        _additionalPaths.Add(path);
        return this;
    }
}
