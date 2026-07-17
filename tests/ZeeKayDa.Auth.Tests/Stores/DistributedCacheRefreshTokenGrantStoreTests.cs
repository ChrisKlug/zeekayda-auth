using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Options;
using ZeeKayDa.Auth.Stores;

namespace ZeeKayDa.Auth.Tests.Stores;

/// <summary>
/// Adapter-level tests for <see cref="DistributedCacheRefreshTokenGrantStore"/> (ADR 0014 §8):
/// grant round-trip, secondary-index maintenance for family/subject revocation, and fail-closed
/// fault propagation. This store is documented dev/test-only and explicitly non-atomic — see its
/// type-level remarks — so no CAS-atomicity assertion is made here (that is covered, with the
/// caveat flagged, by the TestKit conformance kit).
/// </summary>
public sealed class DistributedCacheRefreshTokenGrantStoreTests
{
    private static readonly DateTimeOffset FarFuture = new(2099, 1, 1, 0, 0, 0, TimeSpan.Zero);

    private static IDistributedCache NewCache()
        => new MemoryDistributedCache(new OptionsWrapper<MemoryDistributedCacheOptions>(new MemoryDistributedCacheOptions()));

    private static RefreshTokenGrant BuildGrant(
        StoreKey? handleHash = null,
        string familyId = "family-1",
        string subject = "user-1",
        string clientId = "client-a",
        RefreshGrantStatus status = RefreshGrantStatus.Active,
        DateTimeOffset? familyAbsoluteExpiry = null) =>
        new()
        {
            HandleHash = handleHash ?? NewKey(),
            FamilyId = familyId,
            Subject = subject,
            ClientId = clientId,
            FamilyAbsoluteExpiry = familyAbsoluteExpiry ?? FarFuture,
            ExpiresAt = FarFuture,
            Status = status,
            ProtectedPayload = new byte[] { 1, 2, 3 },
        };

    private static StoreKey NewKey() => new($"grant-{Guid.NewGuid():N}");

    // ── InsertAsync / FindByHandleAsync round-trip ────────────────────────────────────────────────

    [Fact]
    public async Task InsertAsync_then_FindByHandleAsync_round_trips_the_grant()
    {
        var store = new DistributedCacheRefreshTokenGrantStore(NewCache());
        var grant = BuildGrant();

        await store.InsertAsync(grant, CancellationToken.None);
        var result = await store.FindByHandleAsync(grant.HandleHash, CancellationToken.None);

        result.Should().NotBeNull();
        result!.HandleHash.Should().Be(grant.HandleHash);
        result.FamilyId.Should().Be(grant.FamilyId);
        result.Subject.Should().Be(grant.Subject);
        result.ClientId.Should().Be(grant.ClientId);
        result.FamilyAbsoluteExpiry.Should().Be(grant.FamilyAbsoluteExpiry);
        result.ExpiresAt.Should().Be(grant.ExpiresAt);
        result.Status.Should().Be(grant.Status);
        result.ProtectedPayload.ToArray().Should().Equal(grant.ProtectedPayload.ToArray(),
            because: "FluentAssertions' BeEquivalentTo does not structurally compare ReadOnlyMemory<byte>, so compare bytes directly");
    }

    [Fact]
    public async Task FindByHandleAsync_returns_null_for_a_confirmed_absent_handle()
    {
        var store = new DistributedCacheRefreshTokenGrantStore(NewCache());

        var result = await store.FindByHandleAsync(NewKey(), CancellationToken.None);

        result.Should().BeNull();
    }

    // ── TryMarkConsumedAsync ──────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task TryMarkConsumedAsync_returns_true_and_transitions_an_Active_grant_to_Consumed()
    {
        var store = new DistributedCacheRefreshTokenGrantStore(NewCache());
        var grant = BuildGrant();
        await store.InsertAsync(grant, CancellationToken.None);

        var won = await store.TryMarkConsumedAsync(grant.HandleHash, CancellationToken.None);

        won.Should().BeTrue();
        (await store.FindByHandleAsync(grant.HandleHash, CancellationToken.None))!.Status
            .Should().Be(RefreshGrantStatus.Consumed);
    }

    [Fact]
    public async Task TryMarkConsumedAsync_returns_false_for_an_already_Consumed_grant()
    {
        var store = new DistributedCacheRefreshTokenGrantStore(NewCache());
        var grant = BuildGrant(status: RefreshGrantStatus.Consumed);
        await store.InsertAsync(grant, CancellationToken.None);

        var won = await store.TryMarkConsumedAsync(grant.HandleHash, CancellationToken.None);

        won.Should().BeFalse();
    }

    [Fact]
    public async Task TryMarkConsumedAsync_returns_false_for_an_absent_handle()
    {
        var store = new DistributedCacheRefreshTokenGrantStore(NewCache());

        var won = await store.TryMarkConsumedAsync(NewKey(), CancellationToken.None);

        won.Should().BeFalse();
    }

    // ── RevokeFamilyAsync via the secondary index ────────────────────────────────────────────────

    [Fact]
    public async Task RevokeFamilyAsync_marks_every_indexed_grant_in_the_family_as_Revoked()
    {
        var cache = NewCache();
        var store = new DistributedCacheRefreshTokenGrantStore(cache);
        const string familyId = "family-to-revoke";
        var g1 = BuildGrant(familyId: familyId);
        var g2 = BuildGrant(familyId: familyId);
        var g3 = BuildGrant(familyId: "other-family");
        await store.InsertAsync(g1, CancellationToken.None);
        await store.InsertAsync(g2, CancellationToken.None);
        await store.InsertAsync(g3, CancellationToken.None);

        await store.RevokeFamilyAsync(familyId, CancellationToken.None);

        (await store.FindByHandleAsync(g1.HandleHash, CancellationToken.None))!.Status.Should().Be(RefreshGrantStatus.Revoked);
        (await store.FindByHandleAsync(g2.HandleHash, CancellationToken.None))!.Status.Should().Be(RefreshGrantStatus.Revoked);
        (await store.FindByHandleAsync(g3.HandleHash, CancellationToken.None))!.Status.Should().Be(RefreshGrantStatus.Active);
    }

    [Fact]
    public async Task RevokeFamilyAsync_with_unknown_family_id_does_not_throw()
    {
        var store = new DistributedCacheRefreshTokenGrantStore(NewCache());

        var act = async () => await store.RevokeFamilyAsync("unknown-family", CancellationToken.None);

        await act.Should().NotThrowAsync();
    }

    [Fact]
    public async Task RevokeFamilyAsync_is_idempotent()
    {
        var store = new DistributedCacheRefreshTokenGrantStore(NewCache());
        const string familyId = "idempotent-family";
        await store.InsertAsync(BuildGrant(familyId: familyId), CancellationToken.None);

        await store.RevokeFamilyAsync(familyId, CancellationToken.None);
        var act = async () => await store.RevokeFamilyAsync(familyId, CancellationToken.None);

        await act.Should().NotThrowAsync();
    }

    // ── RevokeBySubjectAsync via the secondary index ─────────────────────────────────────────────

    [Fact]
    public async Task RevokeBySubjectAsync_marks_every_indexed_grant_for_the_subject_as_Revoked_across_families()
    {
        var store = new DistributedCacheRefreshTokenGrantStore(NewCache());
        const string subject = "user-to-revoke";
        var g1 = BuildGrant(familyId: "fam-1", subject: subject);
        var g2 = BuildGrant(familyId: "fam-2", subject: subject);
        var g3 = BuildGrant(familyId: "fam-3", subject: "other-user");
        await store.InsertAsync(g1, CancellationToken.None);
        await store.InsertAsync(g2, CancellationToken.None);
        await store.InsertAsync(g3, CancellationToken.None);

        await store.RevokeBySubjectAsync(subject, CancellationToken.None);

        (await store.FindByHandleAsync(g1.HandleHash, CancellationToken.None))!.Status.Should().Be(RefreshGrantStatus.Revoked);
        (await store.FindByHandleAsync(g2.HandleHash, CancellationToken.None))!.Status.Should().Be(RefreshGrantStatus.Revoked);
        (await store.FindByHandleAsync(g3.HandleHash, CancellationToken.None))!.Status.Should().Be(RefreshGrantStatus.Active);
    }

    // ── §8 fail-closed: transport faults must propagate, never be swallowed ────────────────────

    [Fact]
    public async Task InsertAsync_propagates_a_transport_fault_instead_of_swallowing_it()
    {
        var fault = new TransportFaultException();
        var store = new DistributedCacheRefreshTokenGrantStore(new AlwaysFaultingDistributedCache(fault));

        var act = async () => await store.InsertAsync(BuildGrant(), CancellationToken.None);

        await act.Should().ThrowAsync<ZeeKayDaStoreException>()
            .Where(ex => ex.InnerException is TransportFaultException);
    }

    /// <summary>
    /// The dangerous one (ADR 0014 §3/§8): a swallowed fault masked as <see langword="null"/> is
    /// read by the coordinator as "confirmed absent," silently defeating reuse detection.
    /// </summary>
    [Fact]
    public async Task FindByHandleAsync_propagates_a_transport_fault_instead_of_swallowing_it()
    {
        var fault = new TransportFaultException();
        var store = new DistributedCacheRefreshTokenGrantStore(new AlwaysFaultingDistributedCache(fault));

        var act = async () => await store.FindByHandleAsync(NewKey(), CancellationToken.None);

        await act.Should().ThrowAsync<ZeeKayDaStoreException>()
            .Where(ex => ex.InnerException is TransportFaultException);
    }

    [Fact]
    public async Task RevokeFamilyAsync_propagates_a_transport_fault_instead_of_swallowing_it()
    {
        var fault = new TransportFaultException();
        var store = new DistributedCacheRefreshTokenGrantStore(new AlwaysFaultingDistributedCache(fault));

        var act = async () => await store.RevokeFamilyAsync("family-1", CancellationToken.None);

        await act.Should().ThrowAsync<ZeeKayDaStoreException>()
            .Where(ex => ex.InnerException is TransportFaultException);
    }

    [Fact]
    public async Task FindByHandleAsync_wraps_a_corrupted_grant_record_in_ZeeKayDaStoreException_not_returning_null()
    {
        var cache = NewCache();
        var store = new DistributedCacheRefreshTokenGrantStore(cache);
        var grant = BuildGrant();
        await store.InsertAsync(grant, CancellationToken.None);

        // Overwrite the grant's cache entry with un-parseable bytes to simulate corruption.
        await cache.SetAsync(
            $"zkd:rtg:{grant.HandleHash}",
            [0x00, 0x01, 0x02],
            new DistributedCacheEntryOptions { AbsoluteExpiration = FarFuture },
            CancellationToken.None);

        var act = async () => await store.FindByHandleAsync(grant.HandleHash, CancellationToken.None);

        await act.Should().ThrowAsync<ZeeKayDaStoreException>(
            because: "corrupted data is not confirmed absence — it must propagate, not degrade to null (ADR 0014 §3)");
    }

    [Fact]
    public async Task RevokeFamilyAsync_wraps_a_corrupted_family_revocation_index_in_ZeeKayDaStoreException()
    {
        var cache = NewCache();
        var store = new DistributedCacheRefreshTokenGrantStore(cache);
        const string familyId = "family-corrupt-index";
        await cache.SetAsync(
            $"zkd:rtg:family:{familyId}",
            [0x00, 0x01, 0x02],
            new DistributedCacheEntryOptions { AbsoluteExpiration = FarFuture },
            CancellationToken.None);

        var act = async () => await store.RevokeFamilyAsync(familyId, CancellationToken.None);

        await act.Should().ThrowAsync<ZeeKayDaStoreException>(
            because: "a corrupted revocation index is data corruption, not confirmed absence (ADR 0014 §8)");
    }

    [Fact]
    public async Task RevokeBySubjectAsync_wraps_a_corrupted_subject_revocation_index_in_ZeeKayDaStoreException()
    {
        var cache = NewCache();
        var store = new DistributedCacheRefreshTokenGrantStore(cache);
        const string subject = "subject-corrupt-index";
        await cache.SetAsync(
            $"zkd:rtg:subject:{subject}",
            [0x00, 0x01, 0x02],
            new DistributedCacheEntryOptions { AbsoluteExpiration = FarFuture },
            CancellationToken.None);

        var act = async () => await store.RevokeBySubjectAsync(subject, CancellationToken.None);

        await act.Should().ThrowAsync<ZeeKayDaStoreException>(
            because: "a corrupted revocation index is data corruption, not confirmed absence (ADR 0014 §8)");
    }

    [Fact]
    public async Task InsertAsync_wraps_an_index_write_failure_in_ZeeKayDaStoreException()
    {
        var fault = new TransportFaultException();
        var store = new DistributedCacheRefreshTokenGrantStore(new IndexWriteFaultingDistributedCache(NewCache(), fault));

        var act = async () => await store.InsertAsync(BuildGrant(), CancellationToken.None);

        await act.Should().ThrowAsync<ZeeKayDaStoreException>()
            .Where(ex => ex.InnerException == fault);
    }

    // ── Argument guards ───────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task InsertAsync_throws_ArgumentNullException_for_null_grant()
    {
        var store = new DistributedCacheRefreshTokenGrantStore(NewCache());

        var act = async () => await store.InsertAsync(null!, CancellationToken.None);

        await act.Should().ThrowAsync<ArgumentNullException>();
    }

    [Fact]
    public void Constructor_throws_ArgumentNullException_for_null_cache()
    {
        var act = () => new DistributedCacheRefreshTokenGrantStore(null!);

        act.Should().Throw<ArgumentNullException>();
    }

    // ── Helpers ───────────────────────────────────────────────────────────────────────────────────

    private sealed class TransportFaultException : Exception;

    private sealed class AlwaysFaultingDistributedCache(Exception fault) : IDistributedCache
    {
        public byte[]? Get(string key) => throw fault;
        public Task<byte[]?> GetAsync(string key, CancellationToken token = default) => throw fault;
        public void Set(string key, byte[] value, DistributedCacheEntryOptions options) => throw fault;
        public Task SetAsync(string key, byte[] value, DistributedCacheEntryOptions options, CancellationToken token = default) => throw fault;
        public void Refresh(string key) => throw fault;
        public Task RefreshAsync(string key, CancellationToken token = default) => throw fault;
        public void Remove(string key) => throw fault;
        public Task RemoveAsync(string key, CancellationToken token = default) => throw fault;
    }

    /// <summary>
    /// Wraps a real cache; passes grant writes through untouched but faults on writes to either
    /// secondary-index key (family or subject), deterministically exercising the
    /// <c>WriteIndexAsync</c> catch site without disturbing the grant write it follows.
    /// </summary>
    private sealed class IndexWriteFaultingDistributedCache(IDistributedCache inner, Exception fault) : IDistributedCache
    {
        private static bool IsIndexKey(string key) =>
            key.StartsWith("zkd:rtg:family:", StringComparison.Ordinal)
            || key.StartsWith("zkd:rtg:subject:", StringComparison.Ordinal);

        public byte[]? Get(string key) => inner.Get(key);
        public Task<byte[]?> GetAsync(string key, CancellationToken token = default) => inner.GetAsync(key, token);
        public void Set(string key, byte[] value, DistributedCacheEntryOptions options) => inner.Set(key, value, options);

        public Task SetAsync(string key, byte[] value, DistributedCacheEntryOptions options, CancellationToken token = default)
            => IsIndexKey(key) ? throw fault : inner.SetAsync(key, value, options, token);

        public void Refresh(string key) => inner.Refresh(key);
        public Task RefreshAsync(string key, CancellationToken token = default) => inner.RefreshAsync(key, token);
        public void Remove(string key) => inner.Remove(key);
        public Task RemoveAsync(string key, CancellationToken token = default) => inner.RemoveAsync(key, token);
    }
}
