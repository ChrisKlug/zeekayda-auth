namespace ZeeKayDa.Auth.Stores;

/// <summary>
/// The redemption tombstone envelope written by <c>AuthorizationCodeStore</c> (ADR 0013 §7).
/// </summary>
/// <remarks>
/// <see cref="FamilyId"/> is deliberately plaintext — a non-secret random GUID — so that replay
/// detection survives a Data Protection key rotation even when <see cref="ProtectedSecret"/> can
/// no longer be unprotected. The authorization-code store has no secret payload of its own to
/// carry (no family-revocation marker lives here), so <see cref="ProtectedSecret"/> protects an
/// empty placeholder; the field is kept so the shape can be reused, with a real payload, by the
/// later refresh-token store reshape.
/// </remarks>
internal sealed record AuthorizationCodeTombstoneEnvelope
{
    /// <summary>The refresh token family identifier committed at redemption time. Plaintext.</summary>
    public required string FamilyId { get; init; }

    /// <summary>
    /// Data-Protection ciphertext of this store's (currently empty) secret payload. Present so a
    /// well-meaning refactor cannot silently collapse the two-catch-site decrypt asymmetry (§7)
    /// into treating the whole envelope as one opaque blob.
    /// </summary>
    public required byte[] ProtectedSecret { get; init; }
}
