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
    public PemSigningFile? Previous { get; set; }

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
    /// </remarks>
    public PemSigningFile? Next { get; set; }

    /// <summary>
    /// Gets or sets the JWS algorithm every configured slot is signed under. A certificate's key
    /// does not itself declare RS256 vs PS256 — that choice is made here and must match each
    /// certificate's actual key type (RSA algorithms for RSA certificates, EC algorithms for EC
    /// certificates). Defaults to RS256.
    /// </summary>
    public SigningAlgorithm Algorithm { get; set; } = SigningAlgorithm.RS256;
}
