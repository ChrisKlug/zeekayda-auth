using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Time.Testing;
using ZeeKayDa.Auth.Stores;

namespace ZeeKayDa.Auth.Tests.Stores;

/// <summary>
/// Tests for <see cref="DistributedCacheInteractionBackingStore"/>: set, get and remove over
/// <see cref="IDistributedCache"/>, with the entry's expiry handed to the cache as its TTL.
/// </summary>
public sealed class DistributedCacheInteractionBackingStoreTests
{
    private static readonly DateTimeOffset Now = new(2026, 9, 6, 12, 0, 0, TimeSpan.Zero);
    private static readonly DateTimeOffset Later = Now.AddMinutes(30);

    private static StoreKey NewKey() => new($"key-{Guid.NewGuid():N}");

    private static IDistributedCache MemoryCache() =>
        new MemoryDistributedCache(new OptionsWrapper<MemoryDistributedCacheOptions>(new MemoryDistributedCacheOptions()));

    private static DistributedCacheInteractionBackingStore CreateStore(IDistributedCache? cache = null, TimeProvider? time = null) =>
        new(cache ?? MemoryCache(), time ?? new FakeTimeProvider(Now));

    [Fact]
    public async Task SetAsync_then_GetAsync_returns_the_stored_bytes()
    {
        var store = CreateStore();
        var key = NewKey();

        await store.SetAsync(key, new byte[] { 1, 2, 3 }, Later, CancellationToken.None);
        var result = await store.GetAsync(key, CancellationToken.None);

        result!.Value.ToArray().Should().Equal(1, 2, 3);
    }

    [Fact]
    public async Task SetAsync_replaces_a_value_already_at_the_key()
    {
        var store = CreateStore();
        var key = NewKey();

        await store.SetAsync(key, new byte[] { 1 }, Later, CancellationToken.None);
        await store.SetAsync(key, new byte[] { 2 }, Later, CancellationToken.None);

        (await store.GetAsync(key, CancellationToken.None))!.Value.ToArray().Should().Equal(2);
    }

    [Fact]
    public async Task GetAsync_returns_null_for_an_absent_key()
    {
        (await CreateStore().GetAsync(NewKey(), CancellationToken.None)).Should().BeNull();
    }

    [Fact]
    public async Task SetAsync_hands_the_remaining_lifetime_to_the_cache_as_its_TTL()
    {
        var cache = new RecordingCache();
        var store = CreateStore(cache);

        await store.SetAsync(NewKey(), new byte[] { 1 }, Now.AddMinutes(7), CancellationToken.None);

        cache.LastOptions!.AbsoluteExpirationRelativeToNow.Should().Be(TimeSpan.FromMinutes(7));
    }

    [Fact]
    public async Task SetAsync_refuses_a_value_that_is_already_past_its_expiry()
    {
        var store = CreateStore();

        var act = async () => await store.SetAsync(NewKey(), new byte[] { 1 }, Now.AddSeconds(-1), CancellationToken.None);

        await act.Should().ThrowAsync<ZeeKayDaStoreException>();
    }

    [Fact]
    public async Task RemoveAsync_deletes_the_value()
    {
        var store = CreateStore();
        var key = NewKey();
        await store.SetAsync(key, new byte[] { 1 }, Later, CancellationToken.None);

        await store.RemoveAsync(key, CancellationToken.None);

        (await store.GetAsync(key, CancellationToken.None)).Should().BeNull();
    }

    [Fact]
    public async Task A_cache_fault_propagates_rather_than_reading_as_absence()
    {
        var store = CreateStore(new ThrowingCache());

        var act = async () => await store.GetAsync(NewKey(), CancellationToken.None);

        await act.Should().ThrowAsync<InvalidOperationException>(
            "the coordinator wraps faults; the primitive must never swallow one into null");
    }

    private sealed class RecordingCache : IDistributedCache
    {
        public DistributedCacheEntryOptions? LastOptions { get; private set; }

        public byte[]? Get(string key) => null;
        public Task<byte[]?> GetAsync(string key, CancellationToken token = default) => Task.FromResult<byte[]?>(null);
        public void Refresh(string key) { }
        public Task RefreshAsync(string key, CancellationToken token = default) => Task.CompletedTask;
        public void Remove(string key) { }
        public Task RemoveAsync(string key, CancellationToken token = default) => Task.CompletedTask;
        public void Set(string key, byte[] value, DistributedCacheEntryOptions options) => LastOptions = options;

        public Task SetAsync(string key, byte[] value, DistributedCacheEntryOptions options, CancellationToken token = default)
        {
            LastOptions = options;
            return Task.CompletedTask;
        }
    }

    private sealed class ThrowingCache : IDistributedCache
    {
        public byte[]? Get(string key) => throw new InvalidOperationException("cache is down");
        public Task<byte[]?> GetAsync(string key, CancellationToken token = default) => throw new InvalidOperationException("cache is down");
        public void Refresh(string key) => throw new InvalidOperationException("cache is down");
        public Task RefreshAsync(string key, CancellationToken token = default) => throw new InvalidOperationException("cache is down");
        public void Remove(string key) => throw new InvalidOperationException("cache is down");
        public Task RemoveAsync(string key, CancellationToken token = default) => throw new InvalidOperationException("cache is down");
        public void Set(string key, byte[] value, DistributedCacheEntryOptions options) => throw new InvalidOperationException("cache is down");
        public Task SetAsync(string key, byte[] value, DistributedCacheEntryOptions options, CancellationToken token = default) => throw new InvalidOperationException("cache is down");
    }
}
