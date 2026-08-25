using System.Security.Cryptography.X509Certificates;
using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.Windows;

/// <summary>
/// Configuration options for <c>AddWindowsCertificateStoreSigning</c>: the three named signing key
/// slots, the store they are all found in, and the algorithm they are signed under.
/// </summary>
/// <remarks>
/// The slots are read once, at startup, and never re-read — removing or replacing a configured
/// certificate in the store afterwards has no effect on what the process signs with or publishes.
/// Rotating means moving a certificate between slots and restarting: stage the successor as
/// <see cref="Next"/> so its public half is published ahead of time, then promote it to
/// <see cref="Current"/> and demote the certificate it succeeds to <see cref="Previous"/> so tokens
/// it signed still verify.
/// </remarks>
public sealed class WindowsCertificateStoreSigningOptions
{
    /// <summary>
    /// Gets or sets the previously active certificate, published so relying parties can still
    /// verify tokens it signed, or <see langword="null"/> when there is none. Never used to sign,
    /// and its private key is never opened.
    /// </summary>
    public CertificateLookup? Previous { get; set; }

    /// <summary>
    /// Gets or sets the certificate that signs. Required — startup fails when no
    /// <see cref="Current"/> is configured.
    /// </summary>
    public CertificateLookup? Current { get; set; }

    /// <summary>
    /// Gets or sets a certificate staged to become active later, published in advance so relying
    /// parties have already cached it by the time it starts signing, or <see langword="null"/> when
    /// there is none. Never used to sign, and its private key is never opened.
    /// </summary>
    /// <remarks>
    /// A certificate whose <c>NotBefore</c> has not arrived yet belongs here. Configuring one as
    /// <see cref="Current"/> fails startup with <c>signing.signing_key_not_yet_valid</c>.
    /// <para>
    /// <b>Nothing verifies that a certificate was staged here before it was promoted.</b> With a
    /// fixed, operator-edited set of slots there is no observed history to check it against, so
    /// staging a successor long enough ahead for relying parties to have re-fetched the JWKS is the
    /// operator's decision, not something this provider can enforce. Replacing <see cref="Current"/>
    /// in place and restarting is accepted silently, and will reject tokens at any relying party
    /// still holding a cached key set.
    /// </para>
    /// </remarks>
    public CertificateLookup? Next { get; set; }

    /// <summary>
    /// Gets the JWS algorithm every configured slot is signed under. A certificate's key does not
    /// itself declare RS256 vs PS256 — that choice is made by
    /// <c>AddWindowsCertificateStoreSigning</c>'s <c>algorithm</c> argument and must match each
    /// certificate's actual key type (RSA algorithms for RSA certificates, EC algorithms for EC
    /// certificates).
    /// </summary>
    /// <remarks>
    /// The setter is <see langword="internal"/> so the algorithm can be said exactly once, in the
    /// registration argument. A publicly settable one would let a <c>configure</c> callback silently
    /// beat that argument — the "said twice, and the winner is documented nowhere" hazard the two
    /// <c>AddWindowsCertificateStoreSigning</c> overloads exist to prevent for the
    /// <see cref="Current"/> slot.
    /// </remarks>
    public SigningAlgorithm Algorithm { get; internal set; } = SigningAlgorithm.RS256;

    /// <summary>
    /// Gets the store location every slot's certificate is looked up in. Set by
    /// <c>AddWindowsCertificateStoreSigning</c>'s <c>storeLocation</c> argument.
    /// </summary>
    /// <remarks>
    /// <see langword="internal"/> setter for the same reason as <see cref="Algorithm"/>, and with an
    /// additional edge of its own: <see cref="StoreLocation"/>'s default value is a real store
    /// (<see cref="StoreLocation.CurrentUser"/>), so a callback that silently beat the argument
    /// would not fail — it would quietly search the wrong store.
    /// </remarks>
    public StoreLocation StoreLocation { get; internal set; }

    /// <summary>
    /// Gets the store name every slot's certificate is looked up in. Set by
    /// <c>AddWindowsCertificateStoreSigning</c>'s <c>storeName</c> argument.
    /// </summary>
    /// <remarks>
    /// <see langword="internal"/> setter for the same reasons as <see cref="StoreLocation"/>.
    /// </remarks>
    public StoreName StoreName { get; internal set; }
}
