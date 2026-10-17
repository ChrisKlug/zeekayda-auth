using Microsoft.Extensions.Time.Testing;
using ZeeKayDa.Auth.Stores;

namespace ZeeKayDa.Auth.Tests.Stores;

/// <summary>
/// Tests for <see cref="InMemoryAuthorizationCodeBackingStore"/>. This is now a thin persistence
/// primitive — no crypto, no state machine, no outcome selection — so these tests
/// cover only get/insert/remove semantics and the atomicity invariant. Protocol-level behaviour
/// (encryption, expiry, redemption outcomes) is covered by <c>AuthorizationCodeStoreTests</c>.
/// </summary>
public sealed class InMemoryAuthorizationCodeBackingStoreTests
{
    private static readonly DateTimeOffset FarFuture = new(2099, 1, 1, 0, 0, 0, TimeSpan.Zero);
    private static readonly DateTimeOffset Now = new(2026, 10, 16, 12, 0, 0, TimeSpan.Zero);

    private static StoreKey NewKey(string suffix = "") => new StoreKey($"key-{suffix}-{Guid.NewGuid():N}");

    [Fact]
    public async Task TryInsertAsync_returns_true_when_key_is_absent()
    {
        var store = InMemoryStores.AuthorizationCodes();
        var key = NewKey();

        var inserted = await store.TryInsertAsync(key, new byte[] { 1, 2, 3 }, FarFuture, CancellationToken.None);

        inserted.Should().BeTrue();
    }

    [Fact]
    public async Task TryInsertAsync_returns_false_when_key_is_already_present()
    {
        var store = InMemoryStores.AuthorizationCodes();
        var key = NewKey();

        await store.TryInsertAsync(key, new byte[] { 1 }, FarFuture, CancellationToken.None);
        var second = await store.TryInsertAsync(key, new byte[] { 2 }, FarFuture, CancellationToken.None);

        second.Should().BeFalse(because: "the physically-present value must not be overwritten by a second insert");
    }

    [Fact]
    public async Task GetAsync_returns_the_inserted_bytes()
    {
        var store = InMemoryStores.AuthorizationCodes();
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
        var store = InMemoryStores.AuthorizationCodes();

        var result = await store.GetAsync(NewKey(), CancellationToken.None);

        result.Should().BeNull();
    }

    [Fact]
    public async Task RemoveAsync_removes_a_present_key()
    {
        var store = InMemoryStores.AuthorizationCodes();
        var key = NewKey();
        await store.TryInsertAsync(key, new byte[] { 1 }, FarFuture, CancellationToken.None);

        await store.RemoveAsync(key, CancellationToken.None);

        (await store.GetAsync(key, CancellationToken.None)).Should().BeNull();
    }

    [Fact]
    public async Task RemoveAsync_on_an_absent_key_does_not_throw()
    {
        var store = InMemoryStores.AuthorizationCodes();

        var act = async () => await store.RemoveAsync(NewKey(), CancellationToken.None);

        await act.Should().NotThrowAsync(because: "RemoveAsync must be idempotent");
    }

    [Fact]
    public async Task TryInsertAsync_exactly_one_of_many_concurrent_inserts_to_the_same_key_succeeds()
    {
        var store = InMemoryStores.AuthorizationCodes();
        var key = NewKey();
        const int concurrency = 100;
        using var gate = new SemaphoreSlim(0, concurrency);

        var tasks = Enumerable.Range(0, concurrency)
            .Select(_ => Task.Run(async () =>
            {
                await gate.WaitAsync();
                return await store.TryInsertAsync(key, new byte[] { 1 }, FarFuture, CancellationToken.None);
            }))
            .ToArray();

        gate.Release(concurrency);
        var results = await Task.WhenAll(tasks);

        results.Count(r => r).Should().Be(1, because: "exactly one concurrent insert to the same key must win");
    }

    [Fact]
    public async Task TryInsertAsync_respects_pre_cancelled_CancellationToken()
    {
        var store = InMemoryStores.AuthorizationCodes();
        using var cts = new CancellationTokenSource();
        cts.Cancel();

        var act = async () => await store.TryInsertAsync(NewKey(), new byte[] { 1 }, FarFuture, cts.Token);

        await act.Should().ThrowAsync<OperationCanceledException>();
    }

    [Fact]
    public async Task GetAsync_respects_pre_cancelled_CancellationToken()
    {
        var store = InMemoryStores.AuthorizationCodes();
        using var cts = new CancellationTokenSource();
        cts.Cancel();

        var act = async () => await store.GetAsync(NewKey(), cts.Token);

        await act.Should().ThrowAsync<OperationCanceledException>();
    }

    [Fact]
    public async Task RemoveAsync_respects_pre_cancelled_CancellationToken()
    {
        var store = InMemoryStores.AuthorizationCodes();
        using var cts = new CancellationTokenSource();
        cts.Cancel();

        var act = async () => await store.RemoveAsync(NewKey(), cts.Token);

        await act.Should().ThrowAsync<OperationCanceledException>();
    }

    // ── Eviction ──────────────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task TryInsertAsync_removes_an_entry_past_its_expiresAt()
    {
        var time = new FakeTimeProvider(Now);
        var store = InMemoryStores.AuthorizationCodes(time);
        var expired = NewKey();
        await store.TryInsertAsync(expired, new byte[] { 1 }, Now.AddMinutes(1), CancellationToken.None);
        time.SetUtcNow(Now.AddMinutes(2));

        await store.TryInsertAsync(NewKey(), new byte[] { 2 }, FarFuture, CancellationToken.None);

        store.Count.Should().Be(1, "a development host must not hold every code it ever issued");
        (await store.GetAsync(expired, CancellationToken.None)).Should().BeNull();
    }

    [Fact]
    public async Task TryInsertAsync_keeps_an_entry_before_its_expiresAt()
    {
        var time = new FakeTimeProvider(Now);
        var store = InMemoryStores.AuthorizationCodes(time);
        var live = NewKey();
        await store.TryInsertAsync(live, new byte[] { 1 }, Now.AddMinutes(1), CancellationToken.None);
        time.SetUtcNow(Now.AddSeconds(59));

        await store.TryInsertAsync(NewKey(), new byte[] { 2 }, FarFuture, CancellationToken.None);

        (await store.GetAsync(live, CancellationToken.None)).Should().NotBeNull();
    }
}
