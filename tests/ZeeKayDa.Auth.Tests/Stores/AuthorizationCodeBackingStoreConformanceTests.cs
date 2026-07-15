using ZeeKayDa.Auth.Stores;

namespace ZeeKayDa.Auth.Tests.Stores;

/// <summary>
/// Ready-to-derive conformance kit for <see cref="IAuthorizationCodeBackingStore"/> implementers
/// (ADR 0013 §10). Running this against a production backend is a MUST: it exercises the one
/// invariant the CLR cannot verify structurally — that <see cref="IAuthorizationCodeBackingStore.TryInsertAsync"/>
/// is a genuine atomic insert-if-absent, not a read-then-write with a TOCTOU window.
/// </summary>
/// <remarks>
/// Note for third-party implementers: <see cref="StoreKey"/> is constructed only by the
/// framework, so this abstract base class — like any test that must synthesize a
/// <see cref="StoreKey"/> to drive <see cref="IAuthorizationCodeBackingStore"/> directly — can
/// currently only be derived from an assembly with internal access to <c>ZeeKayDa.Auth</c> (see
/// <c>[InternalsVisibleTo]</c>). A genuine external backing-store author cannot yet construct a
/// <see cref="StoreKey"/> to drive this kit from their own test project. This is a known gap
/// flagged for the architect, not an oversight silently worked around here.
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

        results.Count(r => r).Should().Be(1,
            because: "the backend's TryInsertAsync MUST be a genuine atomic insert-if-absent (ADR 0013 §3, §10)");
    }

    [Fact]
    public async Task TryInsertAsync_then_GetAsync_round_trips_the_stored_bytes()
    {
        var store = CreateStore();
        var key = NewKey();
        var value = new byte[] { 4, 5, 6 };

        await store.TryInsertAsync(key, value, FarFuture, CancellationToken.None);
        var result = await store.GetAsync(key, CancellationToken.None);

        result.Should().NotBeNull();
        result!.Value.ToArray().Should().Equal(value);
    }

    [Fact]
    public async Task GetAsync_returns_null_for_a_confirmed_absent_key()
    {
        var store = CreateStore();

        var result = await store.GetAsync(NewKey(), CancellationToken.None);

        result.Should().BeNull();
    }

    [Fact]
    public async Task RemoveAsync_is_idempotent_on_an_absent_key()
    {
        var store = CreateStore();

        var act = async () => await store.RemoveAsync(NewKey(), CancellationToken.None);

        await act.Should().NotThrowAsync();
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

    // ── §3/§8 fail-closed: transport faults must propagate, never be swallowed ─────────────────

    [Fact]
    public async Task TryInsertAsync_propagates_a_transport_fault_instead_of_swallowing_it()
    {
        var fault = new TransportFaultException();
        var store = CreateFaultInjectedStore(fault);
        if (store is null)
            return;

        var act = async () => await store.TryInsertAsync(NewKey(), new byte[] { 1 }, FarFuture, CancellationToken.None);

        await act.Should().ThrowAsync<TransportFaultException>(
            because: "a backing store MUST let a transport fault propagate rather than swallow it (ADR 0013 §3/§8)");
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

        var act = async () => await store.GetAsync(NewKey(), CancellationToken.None);

        await act.Should().ThrowAsync<TransportFaultException>(
            because: "a swallowed fault here reads as \"confirmed absent,\" silently reopening the replay window (ADR 0013 §3/§8)");
    }

    [Fact]
    public async Task RemoveAsync_propagates_a_transport_fault_instead_of_swallowing_it()
    {
        var fault = new TransportFaultException();
        var store = CreateFaultInjectedStore(fault);
        if (store is null)
            return;

        var act = async () => await store.RemoveAsync(NewKey(), CancellationToken.None);

        await act.Should().ThrowAsync<TransportFaultException>(
            because: "a backing store MUST let a transport fault propagate rather than swallow it (ADR 0013 §3/§8)");
    }

    /// <summary>A distinct, clearly-fake exception type used to inject transport faults, so these
    /// tests can never be confused with a real backend exception type.</summary>
    private sealed class TransportFaultException : Exception;
}
