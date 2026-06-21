namespace ZeeKayDa.Auth.Stores;

/// <summary>
/// Configuration options for the distributed-cache-backed token stores
/// (<see cref="DistributedCacheAuthorizationCodeStore"/> and
/// <see cref="DistributedCacheRefreshTokenStore"/>).
/// </summary>
public sealed class DistributedCacheTokenStoreOptions
{
    /// <summary>
    /// Gets or sets the TTL of the family revocation marker key in the distributed cache.
    /// </summary>
    /// <remarks>
    /// <para>
    /// When a refresh token family is revoked (e.g. due to reuse detection), a plaintext
    /// marker key (<c>zkd:rt:family:{H(familyId)}:revoked</c>) is written to the distributed
    /// cache with this TTL. Any subsequent <see cref="IRefreshTokenStore.FindAsync"/> or
    /// <see cref="IRefreshTokenStore.TryConsumeAsync"/> call for a token belonging to the
    /// revoked family finds the marker and returns the appropriate revoked outcome.
    /// </para>
    /// <para>
    /// When <see langword="null"/> (the default), resolved at runtime to
    /// <c>RefreshTokenLifetime + 5 minutes</c>. This ensures revocation markers outlive all
    /// tokens in the family by a small grace margin, preventing a narrow window where a marker
    /// could expire before the last token in the family does.
    /// </para>
    /// <para>
    /// Revocation markers are stored as plaintext (not DP-encrypted). This is intentional:
    /// a Data Protection failure on a revocation marker would fail open into "not revoked",
    /// silently re-enabling a compromised token family. Plaintext markers ensure that
    /// revocation always takes effect regardless of DP key availability (fail-safe).
    /// </para>
    /// </remarks>
    public TimeSpan? FamilyRevocationMarkerTtl { get; set; }
}
