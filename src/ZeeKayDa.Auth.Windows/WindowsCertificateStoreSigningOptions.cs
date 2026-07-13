using System.Security.Cryptography.X509Certificates;
using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.Windows;

/// <summary>
/// Configuration options for <c>AddWindowsCertificateStoreSigning</c>.
/// </summary>
/// <remarks>
/// <see cref="JwtSigningServiceOptions.KeySourceRefreshInterval"/> is inherited from the base class and
/// defaults to 5 minutes. Every registered certificate is re-read from the local store on a cycle
/// where the trusted set has actually changed since the last cycle — see
/// <see cref="WindowsCertificateStoreSigningJwtSigningService.HasKeySetChangedAsync"/> for the
/// cheap, store-access-free check that decides this. It also doubles as the threshold used to
/// warn when a rotated-in certificate's <see cref="X509Certificate2.NotBefore"/> is scheduled too
/// soon relative to how often relying parties are expected to have polled the JWKS (ADR 0011
/// §3.5; see <see cref="SigningKeyRotation.HasTooSoonPendingActivation"/>).
/// </remarks>
public sealed class WindowsCertificateStoreSigningOptions : JwtSigningServiceOptions
{
    private readonly List<string> _additionalThumbprints = [];

    /// <summary>
    /// Gets or sets the thumbprint of the required/primary certificate. Set by
    /// <c>AddWindowsCertificateStoreSigning</c>.
    /// </summary>
    public string Thumbprint { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets the store location to search. Set by <c>AddWindowsCertificateStoreSigning</c>.
    /// </summary>
    public StoreLocation StoreLocation { get; set; }

    /// <summary>
    /// Gets or sets the store name to search. Set by <c>AddWindowsCertificateStoreSigning</c>.
    /// </summary>
    public StoreName StoreName { get; set; }

    /// <summary>
    /// Gets or sets the JWS algorithm to use when signing. A certificate's key does not itself
    /// declare RS256 vs PS256 — that choice is made here and must match the certificate's actual
    /// key type (RSA algorithms for RSA certificates, EC algorithms for EC certificates). Defaults
    /// to RS256.
    /// </summary>
    public SigningAlgorithm Algorithm { get; set; } = SigningAlgorithm.RS256;

    /// <summary>
    /// Gets the thumbprints of every additional certificate registered via
    /// <see cref="AddCertificate"/>, in registration order.
    /// </summary>
    public IReadOnlyList<string> AdditionalThumbprints => _additionalThumbprints;

    /// <summary>
    /// Registers an additional certificate — by thumbprint, from the same
    /// <see cref="StoreLocation"/> and <see cref="StoreName"/> configured on
    /// <c>AddWindowsCertificateStoreSigning</c> — to support rotation with overlapping validity
    /// windows (ADR 0011 §3.5; issue #282's multi-key registration shape).
    /// </summary>
    /// <param name="thumbprint">The additional certificate's thumbprint.</param>
    /// <returns>This instance, so calls can be chained.</returns>
    public WindowsCertificateStoreSigningOptions AddCertificate(string thumbprint)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(thumbprint);
        _additionalThumbprints.Add(ThumbprintFormat.Normalize(thumbprint));
        return this;
    }
}
