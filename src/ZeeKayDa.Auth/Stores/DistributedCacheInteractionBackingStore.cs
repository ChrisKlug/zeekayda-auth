using Microsoft.Extensions.Caching.Distributed;

namespace ZeeKayDa.Auth.Stores;

/// <summary>
/// <see cref="IInteractionBackingStore"/> over the host's <see cref="IDistributedCache"/>; a shared cache such
/// as Redis is a complete answer for a multi-instance host.
/// </summary>
internal sealed class DistributedCacheInteractionBackingStore(
    IDistributedCache cache,
    TimeProvider timeProvider) : IInteractionBackingStore
{
    /// <inheritdoc/>
    public async Task SetAsync(StoreKey key, ReadOnlyMemory<byte> value, DateTimeOffset expiresAt, CancellationToken cancellationToken)
    {
        var ttl = expiresAt - timeProvider.GetUtcNow();
        if (ttl <= TimeSpan.Zero)
            throw new ZeeKayDaStoreException("Cannot store a value that is already past its expiry.");

        var options = new DistributedCacheEntryOptions { AbsoluteExpirationRelativeToNow = ttl };
        await cache.SetAsync(key.ToString(), value.ToArray(), options, cancellationToken).ConfigureAwait(false);
    }

    /// <inheritdoc/>
    public async Task<ReadOnlyMemory<byte>?> GetAsync(StoreKey key, CancellationToken cancellationToken)
    {
        var bytes = await cache.GetAsync(key.ToString(), cancellationToken).ConfigureAwait(false);
        return bytes is null ? null : (ReadOnlyMemory<byte>?)bytes;
    }

    /// <inheritdoc/>
    public async Task RemoveAsync(StoreKey key, CancellationToken cancellationToken)
        => await cache.RemoveAsync(key.ToString(), cancellationToken).ConfigureAwait(false);
}
