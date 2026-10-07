using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.FileSystem;

/// <summary>
/// Configuration options for <c>AddPfxFileSigning</c>: the PFX/PKCS#12 bundles that hold the signing
/// keys, and the algorithm they are signed under.
/// </summary>
/// <remarks>
/// The bundles are read at startup. The framework decides from each certificate's validity window
/// which one signs and which are published, so rotating means adding the successor's bundle and
/// restarting, then removing the old bundle once it is no longer published.
/// </remarks>
public sealed class PfxFileSigningOptions
{
    /// <summary>
    /// Gets the PFX/PKCS#12 bundles that hold the signing keys. At least one is required, and every
    /// one must carry its private key, because any of them may be chosen to sign.
    /// </summary>
    /// <remarks>
    /// A certificate's <c>NotBefore</c> counts as the moment its key was published. A certificate
    /// authority sets that date at issuance, not at deployment, so list a new certificate as soon as it
    /// is issued: one listed more than the lead time after its <c>NotBefore</c> starts signing at the
    /// first restart, before relying parties have seen it in the key set.
    /// </remarks>
    public IList<PfxFile> Files { get; } = [];

    /// <summary>
    /// Gets the JWS algorithm every listed bundle is signed under. A certificate's key does not itself
    /// declare RS256 vs PS256 — that choice is made by <c>AddPfxFileSigning</c>'s <c>algorithm</c>
    /// argument and must match each certificate's actual key type (RSA algorithms for RSA
    /// certificates, EC algorithms for EC certificates).
    /// </summary>
    /// <remarks>
    /// The setter is <see langword="internal"/> so the algorithm is said exactly once, in the
    /// registration argument, and a <c>configure</c> callback cannot silently override it.
    /// </remarks>
    public SigningAlgorithm Algorithm { get; internal set; } = SigningAlgorithm.RS256;
}
