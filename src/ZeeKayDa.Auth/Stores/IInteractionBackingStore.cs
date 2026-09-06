namespace ZeeKayDa.Auth.Stores;

/// <summary>
/// Where the state of an in-flight authorization request lives between the redirects of the
/// authorize flow: opaque, already-encrypted bytes under keys the framework derives, one entry
/// per interaction.
/// </summary>
/// <remarks>
/// <para>
/// Three operations and no atomicity invariant. Unlike the token stores, nothing here decides a
/// race: an interaction is written by the request that starts it, rewritten by the sign-in that
/// authenticates it, and read by the pages that continue it. The one race the flow has — two
/// responses each trying to issue a code for the same interaction — is decided by the
/// authorization code store's atomic insert, not by this contract. That is what makes any
/// distributed cache an adequate backend for it.
/// </para>
/// <para>
/// Expiry is enforced logically by the framework from a copy inside the encrypted value, so a
/// backend that honours <c>expiresAt</c> as a native TTL is tidier, not more correct.
/// Implementations may throw their native exceptions freely; the framework wraps them.
/// </para>
/// </remarks>
internal interface IInteractionBackingStore
{
    /// <summary>Writes <paramref name="value"/> at <paramref name="key"/>, replacing any value already there.</summary>
    /// <param name="key">The framework-derived key.</param>
    /// <param name="value">The opaque bytes to store.</param>
    /// <param name="expiresAt">When the value may be evicted by a backend with native TTL support.</param>
    /// <param name="cancellationToken">A token to cancel the operation.</param>
    ValueTask SetAsync(StoreKey key, ReadOnlyMemory<byte> value, DateTimeOffset expiresAt, CancellationToken cancellationToken);

    /// <summary>
    /// Returns the stored bytes, or <see langword="null"/> when the key is confirmed absent. A
    /// backend failure must propagate rather than read as absence: an interaction that cannot be
    /// read fails closed, and a swallowed fault would report the request expired instead.
    /// </summary>
    /// <param name="key">The framework-derived key.</param>
    /// <param name="cancellationToken">A token to cancel the operation.</param>
    ValueTask<ReadOnlyMemory<byte>?> GetAsync(StoreKey key, CancellationToken cancellationToken);

    /// <summary>Removes the value at <paramref name="key"/> if present. Idempotent.</summary>
    /// <param name="key">The framework-derived key.</param>
    /// <param name="cancellationToken">A token to cancel the operation.</param>
    ValueTask RemoveAsync(StoreKey key, CancellationToken cancellationToken);
}
