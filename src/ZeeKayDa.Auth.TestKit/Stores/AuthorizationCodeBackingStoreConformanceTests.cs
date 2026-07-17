using ZeeKayDa.Auth.Stores;

namespace ZeeKayDa.Auth.TestKit.Stores;

/// <summary>
/// Ready-to-derive conformance kit for <see cref="IAuthorizationCodeBackingStore"/> implementers
/// (ADR 0013 §10). Running this against a production backend is a MUST: it exercises the one
/// invariant the CLR cannot verify structurally — that <see cref="IAuthorizationCodeBackingStore.TryInsertAsync"/>
/// is a genuine atomic insert-if-absent, not a read-then-write with a TOCTOU window.
/// </summary>
/// <remarks>
/// Ships in the <c>ZeeKayDa.Auth.TestKit</c> package, not <c>ZeeKayDa.Auth</c> itself. Reference
/// <c>ZeeKayDa.Auth.TestKit</c> from your own test project, derive this class, and implement
/// <see cref="CreateStore"/> to return your <see cref="IAuthorizationCodeBackingStore"/>. You do
/// not need to construct a <see cref="StoreKey"/> yourself — <see cref="StoreKey"/>'s constructor
/// stays <c>internal</c> to <c>ZeeKayDa.Auth</c> (ADR 0013 §2), and this kit constructs the
/// <see cref="StoreKey"/> values it needs internally via the friend-assembly access granted to
/// <c>ZeeKayDa.Auth.TestKit</c>. This is what lets a genuine third-party backing-store author
/// derive and run the kit from their own external test project.
/// </remarks>
public abstract class AuthorizationCodeBackingStoreConformanceTests
{
    private static readonly DateTimeOffset FarFuture = new(2099, 1, 1, 0, 0, 0, TimeSpan.Zero);

    /// <summary>Creates a fresh, empty store instance under test.</summary>
    protected abstract IAuthorizationCodeBackingStore CreateStore();

    /// <summary>
    /// Override to <see langword="false"/> for backends that do not support atomic
    /// insert-if-absent (e.g. the first-party <c>DistributedCacheAuthorizationCodeBackingStore</c>,
    /// which is documented dev/test-only and explicitly non-atomic). Production backends MUST
    /// support this and MUST NOT override it to <see langword="false"/>.
    /// </summary>
    protected virtual bool SupportsAtomicInsert => true;

    /// <summary>
    /// Override to provide a store instance whose underlying transport always throws
    /// <paramref name="fault"/> on any operation, to prove <c>GetAsync</c>/<c>TryInsertAsync</c>/
    /// <c>RemoveAsync</c> do not swallow transport faults (ADR 0013 §3/§8/§10). Return
    /// <see langword="null"/> if this backend has no injectable transport-failure point (e.g. a
    /// pure in-process data structure with nothing to fail) — the fault-injection tests will then
    /// be skipped for that subclass, and the subclass MUST say so explicitly by overriding and
    /// returning <see langword="null"/> (don't leave the method un-overridden/abstract if there's
    /// truly nothing to inject).
    /// </summary>
    protected virtual IAuthorizationCodeBackingStore? CreateFaultInjectedStore(Exception fault) => null;

    private static StoreKey NewKey() => new($"conformance-{Guid.NewGuid():N}");

    [Fact]
    public async Task TryInsertAsync_exactly_one_of_many_concurrent_inserts_to_the_same_key_succeeds()
    {
        if (!SupportsAtomicInsert)
            return;

        var store = CreateStore();
        var key = NewKey();
        const int concurrency = 50;
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

        // The backend's TryInsertAsync MUST be a genuine atomic insert-if-absent (ADR 0013 §3, §10).
        Assert.Equal(1, results.Count(r => r));
    }

    [Fact]
    public async Task TryInsertAsync_then_GetAsync_round_trips_the_stored_bytes()
    {
        var store = CreateStore();
        var key = NewKey();
        var value = new byte[] { 4, 5, 6 };

        await store.TryInsertAsync(key, value, FarFuture, CancellationToken.None);
        var result = await store.GetAsync(key, CancellationToken.None);

        Assert.NotNull(result);
        Assert.Equal(value, result.Value.ToArray());
    }

    [Fact]
    public async Task GetAsync_returns_null_for_a_confirmed_absent_key()
    {
        var store = CreateStore();

        var result = await store.GetAsync(NewKey(), CancellationToken.None);

        Assert.Null(result);
    }

    [Fact]
    public async Task RemoveAsync_is_idempotent_on_an_absent_key()
    {
        var store = CreateStore();

        await store.RemoveAsync(NewKey(), CancellationToken.None);
    }

    [Fact]
    public async Task RemoveAsync_removes_a_present_key()
    {
        var store = CreateStore();
        var key = NewKey();
        await store.TryInsertAsync(key, new byte[] { 1 }, FarFuture, CancellationToken.None);

        await store.RemoveAsync(key, CancellationToken.None);

        Assert.Null(await store.GetAsync(key, CancellationToken.None));
    }

    // ── §3/§8 fail-closed: transport faults must propagate, never be swallowed ─────────────────

    [Fact]
    public async Task TryInsertAsync_propagates_a_transport_fault_instead_of_swallowing_it()
    {
        var fault = new TransportFaultException();
        var store = CreateFaultInjectedStore(fault);
        if (store is null)
            return;

        // A backing store MUST let a transport fault propagate rather than swallow it (ADR 0013 §3/§8).
        await Assert.ThrowsAsync<TransportFaultException>(
            () => store.TryInsertAsync(NewKey(), new byte[] { 1 }, FarFuture, CancellationToken.None).AsTask());
    }

    /// <summary>
    /// The dangerous one (ADR 0013 §3/§8): if <c>GetAsync</c> swallows a transport fault and
    /// returns <see langword="null"/>, the coordinator reads that as "confirmed absent" — on the
    /// replay path this reads as "code not yet redeemed," silently reopening the replay window
    /// (RFC 9700 §2.1.1).
    /// </summary>
    [Fact]
    public async Task GetAsync_propagates_a_transport_fault_instead_of_swallowing_it()
    {
        var fault = new TransportFaultException();
        var store = CreateFaultInjectedStore(fault);
        if (store is null)
            return;

        await Assert.ThrowsAsync<TransportFaultException>(
            () => store.GetAsync(NewKey(), CancellationToken.None).AsTask());
    }

    [Fact]
    public async Task RemoveAsync_propagates_a_transport_fault_instead_of_swallowing_it()
    {
        var fault = new TransportFaultException();
        var store = CreateFaultInjectedStore(fault);
        if (store is null)
            return;

        // A backing store MUST let a transport fault propagate rather than swallow it (ADR 0013 §3/§8).
        await Assert.ThrowsAsync<TransportFaultException>(
            () => store.RemoveAsync(NewKey(), CancellationToken.None).AsTask());
    }

    /// <summary>A distinct, clearly-fake exception type used to inject transport faults, so these
    /// tests can never be confused with a real backend exception type.</summary>
    private sealed class TransportFaultException : Exception;
}
