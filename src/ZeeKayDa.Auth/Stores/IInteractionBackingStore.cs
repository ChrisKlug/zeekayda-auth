namespace ZeeKayDa.Auth.Stores;

/// <summary>
/// Where an in-flight authorization request's encrypted state lives between redirects, one entry per
/// interaction.
/// </summary>
/// <remarks>
/// No atomicity invariant: the flow's one race, two responses issuing a code, is decided by the code store,
/// so any distributed cache will do. Expiry is enforced from inside the value, so a native TTL is only tidier.
/// </remarks>
internal interface IInteractionBackingStore
{
    /// <summary>Writes <paramref name="value"/> at <paramref name="key"/>, replacing any value already there.</summary>
    /// <param name="key">The framework-derived key.</param>
    /// <param name="value">The opaque bytes to store.</param>
    /// <param name="expiresAt">
    /// When the value may be evicted by a backend with native TTL support. The framework never
    /// writes a value already past it; an implementation may store or refuse one.
    /// </param>
    /// <param name="cancellationToken">A token to cancel the operation.</param>
    Task SetAsync(StoreKey key, ReadOnlyMemory<byte> value, DateTimeOffset expiresAt, CancellationToken cancellationToken);

    /// <summary>
    /// The stored bytes, or <see langword="null"/> only when confirmed absent; a backend fault propagates,
    /// so the interaction fails closed rather than reads as expired.
    /// </summary>
    /// <param name="key">The framework-derived key.</param>
    /// <param name="cancellationToken">A token to cancel the operation.</param>
    Task<ReadOnlyMemory<byte>?> GetAsync(StoreKey key, CancellationToken cancellationToken);

    /// <summary>Removes the value at <paramref name="key"/> if present. Idempotent.</summary>
    /// <param name="key">The framework-derived key.</param>
    /// <param name="cancellationToken">A token to cancel the operation.</param>
    Task RemoveAsync(StoreKey key, CancellationToken cancellationToken);
}
