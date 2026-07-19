using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Time.Testing;
using ZeeKayDa.Auth.Stores;

namespace ZeeKayDa.Auth.Tests.Stores;

/// <summary>
/// Tests for <see cref="DistributedCacheAuthorizationCodeBackingStore"/>. This is now a thin
/// persistence primitive (ADR 0013 §1) — no crypto, no state machine, no outcome selection — so
/// these tests cover only get/insert/remove semantics against <see cref="IDistributedCache"/> and
/// the documented non-atomicity. Protocol-level behaviour is covered by
/// <c>AuthorizationCodeStoreTests</c>.
/// </summary>
public sealed class DistributedCacheAuthorizationCodeBackingStoreTests
{
    private static readonly DateTimeOffset FarFuture = new(2099, 1, 1, 0, 0, 0, TimeSpan.Zero);

    private static StoreKey NewKey(string suffix = "") => new($"key-{suffix}-{Guid.NewGuid():N}");

    private static IDistributedCache CreateMemoryDistributedCache()
        => new MemoryDistributedCache(
            new OptionsWrapper<MemoryDistributedCacheOptions>(new MemoryDistributedCacheOptions()));

    private static DistributedCacheAuthorizationCodeBackingStore CreateStore(
        IDistributedCache? cache = null, TimeProvider? timeProvider = null)
        => new(cache ?? CreateMemoryDistributedCache(), timeProvider ?? TimeProvider.System);

    [Fact]
    public async Task TryInsertAsync_returns_true_when_key_is_absent()
    {
        var store = CreateStore();

        var inserted = await store.TryInsertAsync(NewKey(), new byte[] { 1, 2, 3 }, FarFuture, CancellationToken.None);

        inserted.Should().BeTrue();
    }

    [Fact]
    public async Task TryInsertAsync_returns_false_when_key_is_already_present()
    {
        var store = CreateStore();
        var key = NewKey();

        await store.TryInsertAsync(key, new byte[] { 1 }, FarFuture, CancellationToken.None);
        var second = await store.TryInsertAsync(key, new byte[] { 2 }, FarFuture, CancellationToken.None);

        second.Should().BeFalse();
    }

    [Fact]
    public async Task TryInsertAsync_throws_ZeeKayDaStoreException_for_already_expired_value()
    {
        var startTime = new DateTimeOffset(2090, 1, 1, 12, 0, 0, TimeSpan.Zero);
        var tp = new FakeTimeProvider(startTime);
        var store = CreateStore(timeProvider: tp);

        var act = async () => await store.TryInsertAsync(NewKey(), new byte[] { 1 }, startTime.AddSeconds(-1), CancellationToken.None);

        await act.Should().ThrowAsync<ZeeKayDaStoreException>(
            because: "inserting an already-expired value must be rejected rather than silently clamped");
    }

    [Fact]
    public async Task GetAsync_returns_the_inserted_bytes()
    {
        var store = CreateStore();
        var key = NewKey();
        var value = new byte[] { 9, 8, 7 };

        await store.TryInsertAsync(key, value, FarFuture, CancellationToken.None);
        var result = await store.GetAsync(key, CancellationToken.None);

        result.Should().NotBeNull();
        result!.Value.ToArray().Should().Equal(value);
    }

    [Fact]
    public async Task GetAsync_returns_null_for_an_absent_key()
    {
        var store = CreateStore();

        var result = await store.GetAsync(NewKey(), CancellationToken.None);

        result.Should().BeNull();
    }

    [Fact]
    public async Task RemoveAsync_removes_a_present_key()
    {
        var store = CreateStore();
        var key = NewKey();
        await store.TryInsertAsync(key, new byte[] { 1 }, FarFuture, CancellationToken.None);

        await store.RemoveAsync(key, CancellationToken.None);

        (await store.GetAsync(key, CancellationToken.None)).Should().BeNull();
    }

    [Fact]
    public async Task RemoveAsync_on_an_absent_key_does_not_throw()
    {
        var store = CreateStore();

        var act = async () => await store.RemoveAsync(NewKey(), CancellationToken.None);

        await act.Should().NotThrowAsync(because: "RemoveAsync must be idempotent");
    }

    [Fact]
    public void Constructor_throws_ArgumentNullException_for_null_cache()
    {
        var act = () => new DistributedCacheAuthorizationCodeBackingStore(null!, TimeProvider.System);

        act.Should().Throw<ArgumentNullException>();
    }

    [Fact]
    public void Constructor_throws_ArgumentNullException_for_null_timeProvider()
    {
        var act = () => new DistributedCacheAuthorizationCodeBackingStore(CreateMemoryDistributedCache(), null!);

        act.Should().Throw<ArgumentNullException>();
    }

    [Fact]
    public async Task GetAsync_propagates_an_exception_thrown_by_the_underlying_cache()
    {
        var store = CreateStore(cache: new FaultingDistributedCache(CreateMemoryDistributedCache(), throwOnGet: true));

        var act = async () => await store.GetAsync(NewKey(), CancellationToken.None);

        await act.Should().ThrowAsync<InvalidOperationException>(
            because: "GetAsync must not swallow a transport fault and return null (§3/§8)");
    }

    // ── Helpers ───────────────────────────────────────────────────────────────────────────────────

    private sealed class FaultingDistributedCache : IDistributedCache
    {
        private readonly IDistributedCache _inner;
        private readonly bool _throwOnGet;

        public FaultingDistributedCache(IDistributedCache inner, bool throwOnGet = false)
        {
            _inner = inner;
            _throwOnGet = throwOnGet;
        }

        public byte[]? Get(string key) => _inner.Get(key);

        public Task<byte[]?> GetAsync(string key, CancellationToken token = default)
        {
            if (_throwOnGet)
                throw new InvalidOperationException("Simulated distributed cache Get failure.");
            return _inner.GetAsync(key, token);
        }

        public void Set(string key, byte[] value, DistributedCacheEntryOptions options) => _inner.Set(key, value, options);
        public Task SetAsync(string key, byte[] value, DistributedCacheEntryOptions options, CancellationToken token = default)
            => _inner.SetAsync(key, value, options, token);
        public void Refresh(string key) => _inner.Refresh(key);
        public Task RefreshAsync(string key, CancellationToken token = default) => _inner.RefreshAsync(key, token);
        public void Remove(string key) => _inner.Remove(key);
        public Task RemoveAsync(string key, CancellationToken token = default) => _inner.RemoveAsync(key, token);
    }
}
