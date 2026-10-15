namespace ZeeKayDa.Auth.Stores;

/// <summary>
/// The family a redeemed code started, so a replay can revoke it; plaintext, so a replay is recognised
/// after a key rotation.
/// </summary>
internal sealed record AuthorizationCodeTombstone
{
    /// <summary>The refresh token family identifier committed at redemption time.</summary>
    public required string FamilyId { get; init; }
}
