namespace ZeeKayDa.Auth.Tokens;

/// <summary>
/// What the ring is doing, as one value replaced whole so a consumer never observes a key set without
/// the state it belongs to: <see cref="Signing"/>, <see cref="Stopped"/>, or <see cref="Resuming"/>.
/// </summary>
/// <param name="KeySet">The key set served now.</param>
internal abstract record SigningKeyRingState(SigningKeySet KeySet)
{
    /// <summary>
    /// Why the last read of the source failed, in any state, while the ring serves what it read
    /// before; <see langword="null"/> after a read that completed.
    /// </summary>
    public string? ReadFailure { get; init; }

    /// <summary>A tested signer signs for <see cref="SigningKeyRingState.KeySet"/>'s signing key, chosen from <paramref name="Timeline"/>.</summary>
    internal sealed record Signing(ISigner Signer, SigningKeySet KeySet, SigningKeyTimeline Timeline)
        : SigningKeyRingState(KeySet)
    {
        /// <summary>The key that signs: a key set chosen by the timeline always has one.</summary>
        public SigningKey SigningKey => KeySet.SigningKey!;
    }

    /// <summary>Nothing signs and nothing is published, for <paramref name="Reason"/>, until a read lists usable keys.</summary>
    internal sealed record Stopped(SigningKeySet KeySet, string Reason) : SigningKeyRingState(KeySet);

    /// <summary>
    /// Nothing signs until the handover to the key <paramref name="Timeline"/> makes due completes —
    /// after a stop for <paramref name="Reason"/>, or after the signing key left the list. The
    /// timeline's keys are published meanwhile.
    /// </summary>
    internal sealed record Resuming(SigningKeySet KeySet, SigningKeyTimeline Timeline, string Reason)
        : SigningKeyRingState(KeySet)
    {
        /// <summary>
        /// The <see cref="SigningKey.Kid"/> of the key pair that signed before signing stopped, when its signer
        /// was released only because the source no longer lists that entry.
        /// </summary>
        public string? LastSignedKid { get; init; }
    }
}
