namespace ZeeKayDa.Auth.Stores;

/// <summary>
/// The single extension point for durable storage behind the authorization-code store.
/// Implement this to put records in Redis, SQL, Cosmos, etc.
/// </summary>
/// <remarks>
/// Knows nothing of OAuth, tombstones, encryption or expiry: it stores encrypted bytes under hashed keys,
/// and its one invariant is that <see cref="TryInsertAsync"/> is atomic. Native exceptions may propagate;
/// the framework wraps them as <see cref="ZeeKayDaStoreException"/>.
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
    /// When a backend with native TTL MAY evict the value; expiry is enforced elsewhere, so ignoring it is correct.
    /// </param>
    /// <param name="cancellationToken">A token to cancel the operation.</param>
    /// <returns><see langword="true"/> if inserted; <see langword="false"/> if already present.</returns>
    /// <remarks>
    /// <para>
    /// "No value" means physically absent, not "no live value". Handles are 256-bit random, so a present value
    /// is a genuine collision.
    /// </para>
    /// <para>
    /// The ONE hard invariant: the test and the write MUST be one atomic operation (Redis <c>SET NX</c>, a
    /// unique-constraint <c>INSERT</c>, a conditional Cosmos create). A read-then-write loses single use.
    /// </para>
    /// </remarks>
    Task<bool> TryInsertAsync(StoreKey key, ReadOnlyMemory<byte> value, DateTimeOffset expiresAt, CancellationToken cancellationToken);

    /// <summary>
    /// Returns the stored bytes, or <see langword="null"/> if the key is confirmed absent.
    /// Read-only; never mutates.
    /// </summary>
    /// <param name="key">The already-hashed store key.</param>
    /// <param name="cancellationToken">A token to cancel the operation.</param>
    /// <returns>The stored bytes, or <see langword="null"/> if confirmed absent.</returns>
    /// <remarks>
    /// <strong>Fail-closed:</strong> return <see langword="null"/> ONLY for a confirmed-absent key, and let every
    /// backend fault propagate. A fault returned as <see langword="null"/> reads as "not yet redeemed" and
    /// reopens a replay window.
    /// </remarks>
    Task<ReadOnlyMemory<byte>?> GetAsync(StoreKey key, CancellationToken cancellationToken);

    /// <summary>Removes the value at <paramref name="key"/> if present. Idempotent.</summary>
    /// <param name="key">The already-hashed store key.</param>
    /// <param name="cancellationToken">A token to cancel the operation.</param>
    Task RemoveAsync(StoreKey key, CancellationToken cancellationToken);
}
