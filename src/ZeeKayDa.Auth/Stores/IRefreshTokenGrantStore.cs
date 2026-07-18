namespace ZeeKayDa.Auth.Stores;

/// <summary>
/// The persistence extension point for refresh-token grants. Implement this to store grants in SQL,
/// Cosmos, etc. It owns NO protocol: no hashing (keys arrive pre-hashed as <see cref="StoreKey"/>),
/// no encryption (payloads arrive as ciphertext), no single-use state machine beyond the ONE atomic
/// invariant on <see cref="TryMarkConsumedAsync"/>, no expiry logic, no outcome selection. It stores
/// rows and runs equality queries over their non-secret columns. Native exceptions may propagate
/// freely; the coordinator's Guarded wrapper (ADR 0013 §8) maps them to <see cref="ZeeKayDaStoreException"/>.
/// </summary>
/// <remarks>
/// See ADR 0014 §3 for why the interface is deliberately limited to exactly these five methods —
/// in particular, why there is no bulk remove/cleanup method and no bulk-read-by-family/subject.
/// </remarks>
public interface IRefreshTokenGrantStore
{
    /// <summary>
    /// Insert a new grant. The handle is 256-bit random, so a primary-key collision is a
    /// genuine duplicate/bug — let the unique-constraint violation propagate (the coordinator wraps it).
    /// </summary>
    /// <param name="grant">The grant to insert.</param>
    /// <param name="cancellationToken">A token to cancel the operation.</param>
    ValueTask InsertAsync(RefreshTokenGrant grant, CancellationToken cancellationToken);

    /// <summary>
    /// Return the grant for <paramref name="handleHash"/>, or <see langword="null"/> ONLY if
    /// confirmed absent. Read-only. Fail-closed: on ANY transport/backend fault you MUST let the
    /// exception propagate — you MUST NOT catch it and return <see langword="null"/> (a fault
    /// masked as null is read as "no such token" and silently defeats reuse detection). Same
    /// fail-closed contract as ADR 0013 §3's <c>GetAsync</c>.
    /// </summary>
    /// <param name="handleHash">The already-hashed token handle.</param>
    /// <param name="cancellationToken">A token to cancel the operation.</param>
    ValueTask<RefreshTokenGrant?> FindByHandleAsync(StoreKey handleHash, CancellationToken cancellationToken);

    /// <summary>
    /// THE atomic invariant. Transition the grant at <paramref name="handleHash"/> from
    /// <see cref="RefreshGrantStatus.Active"/> to <see cref="RefreshGrantStatus.Consumed"/> as a
    /// SINGLE atomic operation, and return whether THIS call performed the transition:
    /// <see langword="true"/> iff the row was <see cref="RefreshGrantStatus.Active"/> and is now
    /// <see cref="RefreshGrantStatus.Consumed"/> because of this call; <see langword="false"/> if
    /// the row was not <see cref="RefreshGrantStatus.Active"/> (already consumed or revoked) or is
    /// absent.
    /// </summary>
    /// <param name="handleHash">The already-hashed token handle.</param>
    /// <param name="cancellationToken">A token to cancel the operation.</param>
    /// <remarks>
    /// SQL: <c>UPDATE ... SET status=Consumed WHERE handle=@h AND status=Active</c>; return
    /// <c>rowsAffected==1</c>. Cosmos: conditional replace with <c>IfMatch=etag</c>. Redis: a Lua
    /// script / <c>WATCH-MULTI-EXEC</c> on the key. If this is NOT atomic, single-use enforcement
    /// is lost (two consumers both transition it).
    /// </remarks>
    ValueTask<bool> TryMarkConsumedAsync(StoreKey handleHash, CancellationToken cancellationToken);

    /// <summary>
    /// Set <see cref="RefreshGrantStatus.Revoked"/> for EVERY grant whose <see cref="RefreshTokenGrant.FamilyId"/>
    /// equals <paramref name="familyId"/> AND that already exists at the moment this call evaluates
    /// its predicate. Idempotent. Correctness bar is COMPLETENESS over EXISTING rows — every grant
    /// already in the family, including one inserted concurrently with (but not strictly after) this
    /// call, MUST end up revoked (RFC 9700 §4.13). Mark, do not delete: a still-live token in the
    /// family must remain findable and read as revoked.
    /// </summary>
    /// <param name="familyId">The family identifier to revoke.</param>
    /// <param name="cancellationToken">A token to cancel the operation.</param>
    /// <remarks>
    /// <strong>Known gap, tracked separately (issue #386):</strong> this method does NOT gate future
    /// inserts — a grant <c>InsertAsync</c>'d into <paramref name="familyId"/> strictly after this
    /// call returns (including one for a family with zero live rows at call time) is NOT retroactively
    /// revoked and remains <see cref="RefreshGrantStatus.Active"/>. Closing that gap requires either a
    /// durable revoked-family marker consulted by <see cref="InsertAsync"/> or a fail-closed
    /// insert-time gate — a design change with security weight, not yet made. Do not rely on this
    /// method alone to prevent a family from ever issuing a new live token again.
    /// </remarks>
    ValueTask RevokeFamilyAsync(string familyId, CancellationToken cancellationToken);

    /// <summary>
    /// Set <see cref="RefreshGrantStatus.Revoked"/> for EVERY grant whose <see cref="RefreshTokenGrant.Subject"/>
    /// equals <paramref name="subject"/> AND that already exists at the moment this call evaluates
    /// its predicate. Same completeness bar, and the same known post-call-insert gap (issue #386), as
    /// <see cref="RevokeFamilyAsync"/>. Present so a FUTURE subject-level logout-all is possible; the
    /// endpoint is deferred and no coordinator method calls this yet (ADR 0014 §6). The subject
    /// arrives as cleartext (it is a plain equality predicate, not a keyed lookup) — this control must
    /// never fail to match, which is why the subject is not peppered/keyed (see ADR 0014 sign-off item 1).
    /// </summary>
    /// <param name="subject">The subject identifier to revoke all grants for.</param>
    /// <param name="cancellationToken">A token to cancel the operation.</param>
    ValueTask RevokeBySubjectAsync(string subject, CancellationToken cancellationToken);
}
