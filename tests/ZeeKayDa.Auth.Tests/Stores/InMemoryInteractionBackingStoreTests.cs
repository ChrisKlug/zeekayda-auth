using Microsoft.Extensions.Time.Testing;
using ZeeKayDa.Auth.Stores;

namespace ZeeKayDa.Auth.Tests.Stores;

/// <summary>
/// Tests for <see cref="InMemoryInteractionBackingStore"/>: set, get and remove over a
/// dictionary, with expired entries swept so a development host does not grow without bound.
/// </summary>
public sealed class InMemoryInteractionBackingStoreTests
{
    private static readonly DateTimeOffset Now = new(2026, 9, 6, 12, 0, 0, TimeSpan.Zero);
    private static readonly DateTimeOffset Later = Now.AddMinutes(30);

    private static StoreKey NewKey() => new($"key-{Guid.NewGuid():N}");

    [Fact]
    public async Task SetAsync_then_GetAsync_returns_the_stored_bytes()
    {
        var store = new InMemoryInteractionBackingStore(new FakeTimeProvider(Now));
        var key = NewKey();

        await store.SetAsync(key, new byte[] { 1, 2, 3 }, Later, CancellationToken.None);
        var result = await store.GetAsync(key, CancellationToken.None);

        result!.Value.ToArray().Should().Equal(1, 2, 3);
    }

    [Fact]
    public async Task SetAsync_replaces_a_value_already_at_the_key()
    {
        var store = new InMemoryInteractionBackingStore(new FakeTimeProvider(Now));
        var key = NewKey();

        await store.SetAsync(key, new byte[] { 1 }, Later, CancellationToken.None);
        await store.SetAsync(key, new byte[] { 2 }, Later, CancellationToken.None);

        (await store.GetAsync(key, CancellationToken.None))!.Value.ToArray().Should().Equal(2);
    }

    [Fact]
    public async Task GetAsync_returns_null_for_an_absent_key()
    {
        var store = new InMemoryInteractionBackingStore(new FakeTimeProvider(Now));

        (await store.GetAsync(NewKey(), CancellationToken.None)).Should().BeNull();
    }

    [Fact]
    public async Task GetAsync_returns_null_once_the_entry_has_expired()
    {
        var time = new FakeTimeProvider(Now);
        var store = new InMemoryInteractionBackingStore(time);
        var key = NewKey();
        await store.SetAsync(key, new byte[] { 1 }, Later, CancellationToken.None);

        time.SetUtcNow(Later);

        (await store.GetAsync(key, CancellationToken.None)).Should().BeNull("expiry is exclusive");
    }

    [Fact]
    public async Task SetAsync_sweeps_entries_that_have_expired()
    {
        var time = new FakeTimeProvider(Now);
        var store = new InMemoryInteractionBackingStore(time);
        var expired = NewKey();
        await store.SetAsync(expired, new byte[] { 1 }, Now.AddMinutes(1), CancellationToken.None);
        time.SetUtcNow(Now.AddMinutes(2));

        await store.SetAsync(NewKey(), new byte[] { 2 }, Later, CancellationToken.None);

        store.Count.Should().Be(1, "the expired entry was removed by the sweep, not merely hidden by the expiry check");
    }

    [Fact]
    public async Task SetAsync_leaves_live_entries_alone_when_it_sweeps()
    {
        var time = new FakeTimeProvider(Now);
        var store = new InMemoryInteractionBackingStore(time);
        var live = NewKey();
        await store.SetAsync(live, new byte[] { 1 }, Later, CancellationToken.None);
        time.SetUtcNow(Now.AddMinutes(2));

        await store.SetAsync(NewKey(), new byte[] { 2 }, Later, CancellationToken.None);

        store.Count.Should().Be(2);
        (await store.GetAsync(live, CancellationToken.None)).Should().NotBeNull();
    }

    [Fact]
    public async Task RemoveAsync_deletes_the_value()
    {
        var store = new InMemoryInteractionBackingStore(new FakeTimeProvider(Now));
        var key = NewKey();
        await store.SetAsync(key, new byte[] { 1 }, Later, CancellationToken.None);

        await store.RemoveAsync(key, CancellationToken.None);

        (await store.GetAsync(key, CancellationToken.None)).Should().BeNull();
    }

    [Fact]
    public async Task RemoveAsync_of_an_absent_key_is_a_no_op()
    {
        var store = new InMemoryInteractionBackingStore(new FakeTimeProvider(Now));

        var act = async () => await store.RemoveAsync(NewKey(), CancellationToken.None);

        await act.Should().NotThrowAsync();
    }

    [Fact]
    public async Task Every_operation_honours_a_cancelled_token()
    {
        var store = new InMemoryInteractionBackingStore(new FakeTimeProvider(Now));
        var cancelled = new CancellationToken(canceled: true);

        var set = async () => await store.SetAsync(NewKey(), new byte[] { 1 }, Later, cancelled);
        var get = async () => await store.GetAsync(NewKey(), cancelled);
        var remove = async () => await store.RemoveAsync(NewKey(), cancelled);

        await set.Should().ThrowAsync<OperationCanceledException>();
        await get.Should().ThrowAsync<OperationCanceledException>();
        await remove.Should().ThrowAsync<OperationCanceledException>();
    }
}
