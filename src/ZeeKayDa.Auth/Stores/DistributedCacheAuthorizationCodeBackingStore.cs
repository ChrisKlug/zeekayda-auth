using Microsoft.Extensions.Caching.Distributed;

namespace ZeeKayDa.Auth.Stores;

/// <summary>
/// <see cref="IAuthorizationCodeBackingStore"/> implementation backed by
/// <see cref="IDistributedCache"/>. Suitable for multi-instance dev/test deployments that share a
/// distributed cache (e.g. Redis), but <strong>not recommended for production</strong> use where
/// atomic single-use enforcement is required — see the atomicity note below.
/// </summary>
/// <remarks>
/// <para>
/// <strong>Non-atomic insert (TOCTOU).</strong> <see cref="IDistributedCache"/> exposes no
/// conditional/compare-and-swap write, so <see cref="TryInsertAsync"/> composes a
/// read-then-write, which has a time-of-check-to-time-of-use window: two concurrent inserts to
/// the same key may both observe the key absent before either writes. This can, in the worst
/// case, let two concurrent redemptions of the same code both succeed — violating the
/// single-use requirement of RFC 9700 §2.1.1. For production workloads that require strict
/// single-use enforcement, implement <see cref="IAuthorizationCodeBackingStore"/> against a
/// backend with a native atomic conditional write (e.g. Redis <c>SET NX</c>).
/// </para>
/// <para>
/// This type has no knowledge of OAuth, tombstones, encryption, or expiry — the framework's
/// <c>AuthorizationCodeStore</c> coordinator owns all of that (ADR 0013 §1); this store just
/// holds opaque bytes under already-hashed keys, using the supplied expiry as the cache's
/// native TTL.
/// </para>
/// </remarks>
internal sealed class DistributedCacheAuthorizationCodeBackingStore : IAuthorizationCodeBackingStore
{
    private readonly IDistributedCache _cache;
    private readonly TimeProvider _timeProvider;

    /// <summary>Initialises a new <see cref="DistributedCacheAuthorizationCodeBackingStore"/>.</summary>
    /// <param name="cache">The distributed cache used to store opaque bytes.</param>
    /// <param name="timeProvider">Time provider used to convert absolute expiry into a relative TTL.</param>
    internal DistributedCacheAuthorizationCodeBackingStore(IDistributedCache cache, TimeProvider timeProvider)
    {
        ArgumentNullException.ThrowIfNull(cache);
        ArgumentNullException.ThrowIfNull(timeProvider);

        _cache = cache;
        _timeProvider = timeProvider;
    }

    /// <inheritdoc/>
    public async ValueTask<bool> TryInsertAsync(StoreKey key, ReadOnlyMemory<byte> value, DateTimeOffset expiresAt, CancellationToken cancellationToken)
    {
        var keyString = key.ToString();

        // Non-atomic read-then-write — see type-level doc for the TOCTOU discussion.
        var existing = await _cache.GetAsync(keyString, cancellationToken).ConfigureAwait(false);
        if (existing is not null)
            return false;

        var ttl = expiresAt - _timeProvider.GetUtcNow();
        if (ttl <= TimeSpan.Zero)
            throw new ZeeKayDaStoreException("Cannot insert a value that is already past its expiry.");

        var options = new DistributedCacheEntryOptions { AbsoluteExpirationRelativeToNow = ttl };
        await _cache.SetAsync(keyString, value.ToArray(), options, cancellationToken).ConfigureAwait(false);
        return true;
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
