using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.FileSystem;

/// <summary>
/// Configuration options for <c>AddPemFileSigning</c>: the three named signing key slots and the
/// algorithm they are signed under.
/// </summary>
/// <remarks>
/// The slots are read once, at startup, and never re-read — replacing or deleting a configured file
/// afterwards has no effect on what the process signs with or publishes. Rotating means moving a
/// file between slots and restarting: stage the successor as <see cref="Next"/> so its public half
/// is published ahead of time, then promote it to <see cref="Current"/> and demote the key it
/// succeeds to <see cref="Previous"/> so tokens it signed still verify.
/// </remarks>
public sealed class PemFileSigningOptions
{
    /// <summary>
    /// Gets or sets the previously active key, published so relying parties can still verify tokens
    /// it signed, or <see langword="null"/> when there is none. Never used to sign.
    /// </summary>
    public PemCertificateFile? Previous { get; set; }

    /// <summary>
    /// Gets or sets the key that signs. Required — startup fails when no <see cref="Current"/> is
    /// configured.
    /// </summary>
    public PemSigningFile? Current { get; set; }

    /// <summary>
    /// Gets or sets a key staged to become active later, published in advance so relying parties
    /// have already cached it by the time it starts signing, or <see langword="null"/> when there is
    /// none. Never used to sign.
    /// </summary>
    /// <remarks>
    /// A certificate whose <c>NotBefore</c> has not arrived yet belongs here. Configuring one as
    /// <see cref="Current"/> fails startup with <c>signing.signing_key_not_yet_valid</c>.
    /// <para>
    /// <b>Nothing verifies that a key was staged here before it was promoted.</b> With a fixed,
    /// operator-edited list there is no observed history to check it against, so staging a successor
    /// long enough ahead for relying parties to have re-fetched the JWKS is the operator's decision,
    /// not something this provider can enforce. Replacing <see cref="Current"/> in place and
    /// restarting is accepted silently, and will reject tokens at any relying party still holding a
    /// cached key set.
    /// </para>
    /// </remarks>
    public PemCertificateFile? Next { get; set; }

    /// <summary>
    /// Gets the JWS algorithm every configured slot is signed under. A certificate's key does not
    /// itself declare RS256 vs PS256 — that choice is made by <c>AddPemFileSigning</c>'s
    /// <c>algorithm</c> argument and must match each certificate's actual key type (RSA algorithms
    /// for RSA certificates, EC algorithms for EC certificates).
    /// </summary>
    /// <remarks>
    /// The setter is <see langword="internal"/> so the algorithm can be said exactly once, in the
    /// registration argument. A publicly settable one would let a <c>configure</c> callback silently
    /// beat that argument — the same "said twice, and the winner is documented nowhere" hazard the
    /// two <c>AddPemFileSigning</c> overloads exist to prevent for the <see cref="Current"/> slot.
    /// </remarks>
    public SigningAlgorithm Algorithm { get; internal set; } = SigningAlgorithm.RS256;
}
