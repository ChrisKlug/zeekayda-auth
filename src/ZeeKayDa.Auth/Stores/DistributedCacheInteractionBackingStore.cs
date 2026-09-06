using Microsoft.Extensions.Caching.Distributed;

namespace ZeeKayDa.Auth.Stores;

/// <summary>
/// <see cref="IInteractionBackingStore"/> over the host's <see cref="IDistributedCache"/>. Set,
/// get and remove are exactly what a distributed cache provides, so a shared cache such as Redis
/// is a complete answer for a multi-instance host, with nothing bespoke on top.
/// </summary>
/// <remarks>
/// The one backend that is not adequate is the per-process <c>MemoryDistributedCache</c>, which
/// despite its name is shared with nothing: an authorization request started on one instance
/// cannot be completed by another. Startup verification refuses it outside Development.
/// </remarks>
internal sealed class DistributedCacheInteractionBackingStore : IInteractionBackingStore
{
    private readonly IDistributedCache _cache;
    private readonly TimeProvider _timeProvider;

    public DistributedCacheInteractionBackingStore(IDistributedCache cache, TimeProvider timeProvider)
    {
        ArgumentNullException.ThrowIfNull(cache);
        ArgumentNullException.ThrowIfNull(timeProvider);

        _cache = cache;
        _timeProvider = timeProvider;
    }

    /// <inheritdoc/>
    public async ValueTask SetAsync(StoreKey key, ReadOnlyMemory<byte> value, DateTimeOffset expiresAt, CancellationToken cancellationToken)
    {
        var ttl = expiresAt - _timeProvider.GetUtcNow();
        if (ttl <= TimeSpan.Zero)
            throw new ZeeKayDaStoreException("Cannot store a value that is already past its expiry.");

        var options = new DistributedCacheEntryOptions { AbsoluteExpirationRelativeToNow = ttl };
        await _cache.SetAsync(key.ToString(), value.ToArray(), options, cancellationToken).ConfigureAwait(false);
    }

    /// <inheritdoc/>
    public async ValueTask<ReadOnlyMemory<byte>?> GetAsync(StoreKey key, CancellationToken cancellationToken)
    {
        var bytes = await _cache.GetAsync(key.ToString(), cancellationToken).ConfigureAwait(false);
        return bytes is null ? null : (ReadOnlyMemory<byte>?)bytes;
    }

    /// <inheritdoc/>
    public async ValueTask RemoveAsync(StoreKey key, CancellationToken cancellationToken)
        => await _cache.RemoveAsync(key.ToString(), cancellationToken).ConfigureAwait(false);
}
