namespace ZeeKayDa.Auth.Stores;

/// <summary>
/// The persistence extension point for refresh-token grants, for SQL, Cosmos and the like. It owns no
/// protocol: keys arrive hashed as <see cref="StoreKey"/>, payloads arrive encrypted, and its one
/// invariant is that <see cref="TryMarkConsumedAsync"/> is atomic. Native exceptions may propagate; the
/// framework maps them to <see cref="ZeeKayDaStoreException"/>.
/// </summary>
public interface IRefreshTokenBackingStore
{
    /// <summary>
    /// Inserts a new grant. The handle is 256-bit random, so let a primary-key violation propagate: it is a bug.
    /// </summary>
    /// <param name="grant">The grant to insert.</param>
    /// <param name="cancellationToken">A token to cancel the operation.</param>
    Task InsertAsync(RefreshTokenGrant grant, CancellationToken cancellationToken);

    /// <summary>
    /// The grant for <paramref name="handleHash"/>, or <see langword="null"/> only when confirmed absent. A
    /// backend fault MUST propagate, never become <see langword="null"/>, which would read as "no such token"
    /// and defeat reuse detection.
    /// </summary>
    /// <param name="handleHash">The already-hashed token handle.</param>
    /// <param name="cancellationToken">A token to cancel the operation.</param>
    Task<RefreshTokenGrant?> FindByHandleAsync(StoreKey handleHash, CancellationToken cancellationToken);

    /// <summary>
    /// Atomically moves the grant from <see cref="RefreshGrantStatus.Active"/> to
    /// <see cref="RefreshGrantStatus.Consumed"/>, returning whether this call did so; <see langword="false"/>
    /// when it was not active or is absent.
    /// </summary>
    /// <param name="handleHash">The already-hashed token handle.</param>
    /// <param name="cancellationToken">A token to cancel the operation.</param>
    /// <remarks>
    /// SQL: <c>UPDATE ... SET status=Consumed WHERE handle=@h AND status=Active</c>, true when one row
    /// changed. Cosmos: conditional replace with <c>IfMatch=etag</c>. Redis: a Lua script. Without atomicity
    /// two consumers both succeed, and single use is lost.
    /// </remarks>
    Task<bool> TryMarkConsumedAsync(StoreKey handleHash, CancellationToken cancellationToken);

    /// <summary>
    /// Records <paramref name="familyId"/> as revoked, then marks every grant already in it
    /// <see cref="RefreshGrantStatus.Revoked"/>, including one inserted concurrently (RFC 9700 §4.13).
    /// Idempotent. Mark, never delete: a live token must still be found and read as revoked.
    /// </summary>
    /// <param name="familyId">The family identifier to revoke.</param>
    /// <param name="rememberUntil">
    /// How long the record must be kept: <see cref="IsFamilyRevokedAsync"/> MUST answer
    /// <see langword="true"/> for this family until then, and MAY forget it afterwards, when no
    /// grant of the family can still be live. A repeat call never shortens it.
    /// </param>
    /// <param name="cancellationToken">A token to cancel the operation.</param>
    /// <remarks>
    /// The record is not a grant row. Commit it before marking rows, not in one transaction, so a fault while
    /// marking still leaves the family revoked. The family may have no rows yet, when a code is replayed
    /// before its first refresh token is stored.
    /// </remarks>
    Task RevokeFamilyAsync(string familyId, DateTimeOffset rememberUntil, CancellationToken cancellationToken);

    /// <summary>
    /// Marks every grant already existing for <paramref name="subject"/> revoked, as
    /// <see cref="RevokeFamilyAsync"/> does. Nothing calls it yet. The subject arrives in cleartext, not keyed,
    /// so this control can never fail to match.
    /// </summary>
    /// <param name="subject">The subject identifier to revoke all grants for.</param>
    /// <param name="cancellationToken">A token to cancel the operation.</param>
    Task RevokeBySubjectAsync(string subject, CancellationToken cancellationToken);

    /// <summary>
    /// Whether <see cref="RevokeFamilyAsync"/> recorded <paramref name="familyId"/> and the record is still
    /// kept; checked before a grant's own status, so a successor inserted after a revoke is caught.
    /// </summary>
    /// <param name="familyId">The family identifier to check.</param>
    /// <param name="cancellationToken">A token to cancel the operation.</param>
    /// <remarks>
    /// MUST be a strongly consistent read, and MUST throw on a fault rather than return
    /// <see langword="false"/>: either failure reads as "not revoked" and fails open.
    /// SQL: <c>SELECT EXISTS(SELECT 1 FROM revoked_families WHERE family_id=@f)</c>.
    /// </remarks>
    Task<bool> IsFamilyRevokedAsync(string familyId, CancellationToken cancellationToken);
}
