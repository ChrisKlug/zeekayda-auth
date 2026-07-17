namespace ZeeKayDa.Auth.Stores;

/// <summary>
/// The single extension point for durable storage behind the authorization-code store
/// (ADR 0013 §3). Implement this to put records in Redis, SQL, Cosmos, etc.
/// </summary>
/// <remarks>
/// This interface has NO knowledge of OAuth, tombstones, encryption, or expiry semantics — it
/// stores opaque, already-encrypted bytes under already-hashed keys. The correctness of the
/// redemption protocol does not depend on this implementation beyond the ONE atomicity
/// invariant on <see cref="TryInsertAsync"/>. Implementations MAY throw their native exceptions
/// freely; the framework's <c>AuthorizationCodeStore</c> coordinator wraps them as
/// <see cref="ZeeKayDaStoreException"/> (ADR 0013 §8).
/// </remarks>
public interface IAuthorizationCodeBackingStore
{
    /// <summary>
    /// Atomically inserts <paramref name="value"/> at <paramref name="key"/> only if no value
    /// currently exists at the key.
    /// </summary>
    /// <param name="key">The already-hashed store key.</param>
    /// <param name="value">The opaque bytes to store.</param>
    /// <param name="expiresAt">
    /// The point at which a backend with native TTL support MAY evict this value. The
    /// coordinator enforces expiry logically and does not rely on this eviction, so ignoring
    /// this value is correct, just less tidy.
    /// </param>
    /// <param name="cancellationToken">A token to cancel the operation.</param>
    /// <returns><see langword="true"/> if inserted; <see langword="false"/> if already present.</returns>
    /// <remarks>
    /// <para>
    /// "No value exists" means physically absent, not "no <em>live</em> value" — logical expiry
    /// is the coordinator's concern, not this primitive's. Handles are 256-bit random, so a key
    /// is never legitimately reused and a physically-present value always means a genuine
    /// collision.
    /// </para>
    /// <para>
    /// This is the ONE hard invariant: the insert-if-absent test and the write MUST be a single
    /// atomic operation (Redis <c>SET NX</c>, a unique-constraint <c>INSERT</c>, a conditional
    /// Cosmos create). A non-atomic <c>if (!Exists(key)) Insert(key)</c> has a TOCTOU window and
    /// loses single-use enforcement — never use a read-then-write.
    /// </para>
    /// </remarks>
    ValueTask<bool> TryInsertAsync(StoreKey key, ReadOnlyMemory<byte> value, DateTimeOffset expiresAt, CancellationToken cancellationToken);

    /// <summary>
    /// Returns the stored bytes, or <see langword="null"/> if the key is confirmed absent.
    /// Read-only; never mutates.
    /// </summary>
    /// <param name="key">The already-hashed store key.</param>
    /// <param name="cancellationToken">A token to cancel the operation.</param>
    /// <returns>The stored bytes, or <see langword="null"/> if confirmed absent.</returns>
    /// <remarks>
    /// <strong>Fail-closed contract:</strong> return <see langword="null"/> ONLY for a
    /// confirmed-absent key. On ANY transport/backend failure (timeout, connection drop,
    /// deserialization error, auth failure) the implementation MUST let the exception propagate
    /// — it MUST NOT catch it and return <see langword="null"/>. A swallowed fault that returns
    /// <see langword="null"/> is read by the coordinator as "no tombstone ⇒ code not yet
    /// redeemed," silently re-opening a replay window. Throwing on fault is a contractual
    /// obligation, not a nicety.
    /// </remarks>
    ValueTask<ReadOnlyMemory<byte>?> GetAsync(StoreKey key, CancellationToken cancellationToken);

    /// <summary>Removes the value at <paramref name="key"/> if present. Idempotent.</summary>
    /// <param name="key">The already-hashed store key.</param>
    /// <param name="cancellationToken">A token to cancel the operation.</param>
    ValueTask RemoveAsync(StoreKey key, CancellationToken cancellationToken);
}
