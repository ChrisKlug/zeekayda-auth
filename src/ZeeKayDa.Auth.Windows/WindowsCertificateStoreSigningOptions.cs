using System.Security.Cryptography.X509Certificates;
using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.Windows;

/// <summary>
/// Configuration options for <c>AddWindowsCertificateStoreSigning</c>: the certificates that hold the
/// signing keys, the store they are all found in, and the algorithm they are signed under.
/// </summary>
/// <remarks>
/// The certificates are read at startup. The framework decides from each certificate's validity
/// window which one signs and which are published, so rotating means adding the successor and
/// restarting, then removing the old certificate once it is no longer published.
/// </remarks>
public sealed class WindowsCertificateStoreSigningOptions
{
    /// <summary>
    /// Gets the certificates that hold the signing keys. At least one is required, and every one must
    /// have a private key this process can use, because any of them may be chosen to sign.
    /// </summary>
    /// <remarks>
    /// A certificate's <c>NotBefore</c> counts as the moment its key was published. A certificate
    /// authority sets that date at issuance, not at deployment, so list a new certificate as soon as it
    /// is issued: one listed more than the lead time after its <c>NotBefore</c> starts signing at the
    /// first restart, before relying parties have seen it in the key set.
    /// </remarks>
    public IList<CertificateLookup> Certificates { get; } = [];

    /// <summary>
    /// Gets the JWS algorithm every listed certificate is signed under. A certificate's key does not
    /// itself declare RS256 vs PS256 — that choice is made by
    /// <c>AddWindowsCertificateStoreSigning</c>'s <c>algorithm</c> argument and must match each
    /// certificate's actual key type (RSA algorithms for RSA certificates, EC algorithms for EC
    /// certificates).
    /// </summary>
    /// <remarks>
    /// The setter is <see langword="internal"/> so the algorithm is said exactly once, in the
    /// registration argument, and a <c>configure</c> callback cannot silently override it.
    /// </remarks>
    public SigningAlgorithm Algorithm { get; internal set; } = SigningAlgorithm.RS256;

    /// <summary>
    /// Gets the store location every listed certificate is looked up in. Set by
    /// <c>AddWindowsCertificateStoreSigning</c>'s <c>storeLocation</c> argument.
    /// </summary>
    /// <remarks>
    /// <see langword="internal"/> setter for the same reason as <see cref="Algorithm"/>: a callback
    /// that silently beat the argument would search a different store than the registration named,
    /// and unlike a wrong algorithm that mismatch is invisible until the certificate is not found.
    /// (Leaving it unset entirely is not the hazard — <see langword="default"/> is <c>0</c>, which
    /// is not a defined <see cref="StoreLocation"/> member at all and which <c>X509Store</c>
    /// rejects. The hazard is a callback setting it to a real but unintended store.)
    /// </remarks>
    public StoreLocation StoreLocation { get; internal set; }

    /// <summary>
    /// Gets the store name every listed certificate is looked up in. Set by
    /// <c>AddWindowsCertificateStoreSigning</c>'s <c>storeName</c> argument.
    /// </summary>
    /// <remarks>
    /// <see langword="internal"/> setter for the same reasons as <see cref="StoreLocation"/>.
    /// </remarks>
    public StoreName StoreName { get; internal set; }
}
