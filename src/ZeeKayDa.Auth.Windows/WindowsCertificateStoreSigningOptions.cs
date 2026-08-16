using System.Security.Cryptography.X509Certificates;
using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.Windows;

/// <summary>
/// Configuration options for <c>AddWindowsCertificateStoreSigning</c>.
/// </summary>
/// <remarks>
/// <para>
/// The complete set of registered thumbprints is fixed at configuration time, and the only thing
/// that ever advances is the wall clock crossing each certificate's <c>NotBefore</c>/<c>NotAfter</c> —
/// mapped onto each key's
/// <see cref="ZeeKayDa.Auth.Tokens.KeyListing.ActivateAt"/>/<see cref="ZeeKayDa.Auth.Tokens.KeyListing.ExpiresAt"/>.
/// <see cref="KeySetOptions.PublicationLead"/> is inherited from <see cref="KeySetOptions"/> — see
/// that type's remarks for what it governs (an advisory too-soon-activation startup warning, not a
/// re-download cadence — there is nothing to re-download on this tier).
/// </para>
/// <para>
/// Picking up a rotated-in, removed, or replaced certificate requires a process restart: this
/// provider's <c>ListKeysAsync</c> runs exactly once, ever, for the lifetime of a service instance —
/// register the successor certificate via <see cref="AddCertificate"/> ahead of its intended
/// activation time and redeploy, rather than expecting a live reload.
/// </para>
/// </remarks>
public sealed class WindowsCertificateStoreSigningOptions : KeySetOptions
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
    /// windows.
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
