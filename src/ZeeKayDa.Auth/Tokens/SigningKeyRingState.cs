namespace ZeeKayDa.Auth.Tokens;

/// <summary>
/// What the ring is doing, replaced whole so a key set is never seen without its state.
/// </summary>
/// <param name="KeySet">The key set served now.</param>
internal abstract record SigningKeyRingState(SigningKeySet KeySet)
{
    /// <summary>Why the last read failed while the ring serves what it read before; <see langword="null"/> after a good read.</summary>
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

    /// <summary>Nothing signs until the handover to the key <paramref name="Timeline"/> makes due completes; its keys are published meanwhile.</summary>
    internal sealed record Resuming(SigningKeySet KeySet, SigningKeyTimeline Timeline, string Reason)
        : SigningKeyRingState(KeySet)
    {
        /// <summary>The kid that signed before its entry was unlisted, when that is why signing stopped.</summary>
        public string? LastSignedKid { get; init; }
    }
}
