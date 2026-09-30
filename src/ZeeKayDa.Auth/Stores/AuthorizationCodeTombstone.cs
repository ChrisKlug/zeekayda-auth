namespace ZeeKayDa.Auth.Stores;

/// <summary>
/// The redemption tombstone written by <c>AuthorizationCodeStore</c>: the family a redeemed code
/// started, so a replay can revoke it.
/// </summary>
/// <remarks>
/// Plaintext, with no Data Protection: <see cref="FamilyId"/> is a non-secret random identifier,
/// and a replay must be recognised even after the key that protected the code has rotated.
/// </remarks>
internal sealed record AuthorizationCodeTombstone
{
    /// <summary>The refresh token family identifier committed at redemption time.</summary>
    public required string FamilyId { get; init; }
}
