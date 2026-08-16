using ZeeKayDa.Auth.Stores;

namespace ZeeKayDa.Auth.TestKit.Stores;

/// <summary>
/// Ready-to-derive conformance kit for <see cref="IRefreshTokenGrantStore"/> implementers. Running
/// this against a production backend is a MUST: it exercises the invariants the CLR cannot verify
/// structurally — revocation completeness by family and by subject (including a
/// grant inserted mid-revoke, the race a drifting secondary index loses), the CAS atomicity
/// invariant on <see cref="IRefreshTokenGrantStore.TryMarkConsumedAsync"/>, and fail-closed fault
/// propagation on <see cref="IRefreshTokenGrantStore.FindByHandleAsync"/> and
/// <see cref="IRefreshTokenGrantStore.TryMarkConsumedAsync"/>.
/// </summary>
/// <remarks>
/// Ships in the <c>ZeeKayDa.Auth.TestKit</c> package, not <c>ZeeKayDa.Auth</c> itself. Reference
/// <c>ZeeKayDa.Auth.TestKit</c> from your own test project, derive this class, and implement
/// <see cref="CreateStore"/> to return your <see cref="IRefreshTokenGrantStore"/>. You do not need
/// to construct a <see cref="StoreKey"/> yourself — its constructor stays <c>internal</c> to
/// <c>ZeeKayDa.Auth</c>, and this kit constructs the values it needs internally via the
/// friend-assembly access granted to <c>ZeeKayDa.Auth.TestKit</c>.
/// </remarks>
public abstract class RefreshTokenGrantStoreConformanceTests
{
    private static readonly DateTimeOffset FarFuture = new(2099, 1, 1, 0, 0, 0, TimeSpan.Zero);

    /// <summary>Creates a fresh, empty store instance under test.</summary>
    protected abstract IRefreshTokenGrantStore CreateStore();

    /// <summary>
    /// Override to <see langword="false"/> for backends that do not support atomic
    /// compare-and-set (e.g. the first-party <c>DistributedCacheRefreshTokenGrantStore</c>, which
    /// is documented dev/test-only and explicitly non-atomic). Production backends MUST support
    /// this and MUST NOT override it to <see langword="false"/>.
    /// </summary>
    protected virtual bool SupportsAtomicConsume => true;

    /// <summary>
    /// Override to <see langword="false"/> for backends whose family/subject revocation cannot be
    /// proven complete against a grant inserted concurrently with the revoke call — e.g. a
    /// non-transactional secondary-index backend like the first-party
    /// <c>DistributedCacheRefreshTokenGrantStore</c> (a documented dev/test caveat). Production
    /// backends MUST support this and MUST NOT override it to <see langword="false"/>.
    /// </summary>
    protected virtual bool SupportsMidRevokeInsertCompleteness => true;

    /// <summary>
    /// Override to provide a store instance whose underlying transport always throws
    /// <paramref name="fault"/> on any operation, to prove <c>FindByHandleAsync</c> does not
    /// swallow transport faults. Return <see langword="null"/> if this
    /// backend has no injectable transport-failure point — the fault-injection test will then be
    /// skipped for that subclass, and the subclass MUST say so explicitly by overriding and
    /// returning <see langword="null"/>.
    /// </summary>
    protected virtual IRefreshTokenGrantStore? CreateFaultInjectedStore(Exception fault) => null;

    private static StoreKey NewKey() => new($"conformance-{Guid.NewGuid():N}");

    private static RefreshTokenGrant NewGrant(
        string familyId,
        string subject = "conformance-subject",
        string clientId = "conformance-client",
        RefreshGrantStatus status = RefreshGrantStatus.Active) =>
        new()
        {
            HandleHash = NewKey(),
            FamilyId = familyId,
            Subject = subject,
            ClientId = clientId,
            FamilyAbsoluteExpiry = FarFuture,
            ExpiresAt = FarFuture,
            Status = status,
            ProtectedPayload = new byte[] { 1, 2, 3 },
        };

    // ── Revocation completeness by family, including a grant inserted mid-revoke ────────────────

    [Fact]
    public async Task RevokeFamilyAsync_marks_every_grant_in_the_family_as_Revoked_including_one_inserted_mid_revoke()
    {
        var store = CreateStore();
        var familyId = $"family-{Guid.NewGuid():N}";
        const int preExistingCount = 10;

        var preExisting = Enumerable.Range(0, preExistingCount)
            .Select(_ => NewGrant(familyId))
            .ToList();
        foreach (var grant in preExisting)
            await store.InsertAsync(grant, CancellationToken.None);

        if (!SupportsMidRevokeInsertCompleteness)
        {
            // A non-transactional secondary-index backend cannot be proven complete against this
            // race; only the pre-existing-grants portion is asserted.
            await store.RevokeFamilyAsync(familyId, CancellationToken.None);
            foreach (var grant in preExisting)
            {
                var result = await store.FindByHandleAsync(grant.HandleHash, CancellationToken.None);
                Assert.Equal(RefreshGrantStatus.Revoked, result!.Status);
            }
            return;
        }

        var midRevokeGrant = NewGrant(familyId);
        using var insertStarted = new SemaphoreSlim(0, 1);
        using var revokeMayProceed = new SemaphoreSlim(0, 1);

        var insertTask = Task.Run(async () =>
        {
            insertStarted.Release();
            await revokeMayProceed.WaitAsync();
            await store.InsertAsync(midRevokeGrant, CancellationToken.None);
        });

        await insertStarted.WaitAsync();
        revokeMayProceed.Release();
        // Give the insert a genuine chance to race with the revoke rather than always losing.
        await Task.WhenAll(insertTask, store.RevokeFamilyAsync(familyId, CancellationToken.None).AsTask());

        foreach (var grant in preExisting.Append(midRevokeGrant))
        {
            var result = await store.FindByHandleAsync(grant.HandleHash, CancellationToken.None);
            Assert.NotNull(result);
            Assert.Equal(RefreshGrantStatus.Revoked, result!.Status);
        }
    }

    /// <summary>
    /// <c>RevokeFamilyAsync</c> is documented "Idempotent" and its completeness bar is EVERY
    /// existing grant in the family, not just <see cref="RefreshGrantStatus.Active"/>
    /// ones — a grant already <see cref="RefreshGrantStatus.Consumed"/> before the call still ends up
    /// <see cref="RefreshGrantStatus.Revoked"/>, and calling the method again is a safe no-op that
    /// leaves every grant's status unchanged.
    /// </summary>
    [Fact]
    public async Task RevokeFamilyAsync_is_idempotent_and_also_revokes_an_already_Consumed_grant()
    {
        var store = CreateStore();
        var familyId = $"family-{Guid.NewGuid():N}";
        var activeGrant = NewGrant(familyId);
        var consumedGrant = NewGrant(familyId);
        await store.InsertAsync(activeGrant, CancellationToken.None);
        await store.InsertAsync(consumedGrant, CancellationToken.None);
        Assert.True(await store.TryMarkConsumedAsync(consumedGrant.HandleHash, CancellationToken.None));

        await store.RevokeFamilyAsync(familyId, CancellationToken.None);
        await store.RevokeFamilyAsync(familyId, CancellationToken.None);

        foreach (var grant in new[] { activeGrant, consumedGrant })
        {
            var result = await store.FindByHandleAsync(grant.HandleHash, CancellationToken.None);
            Assert.NotNull(result);
            Assert.Equal(RefreshGrantStatus.Revoked, result!.Status);
        }
    }

    [Fact]
    public async Task RevokeFamilyAsync_does_not_affect_grants_in_a_different_family()
    {
        var store = CreateStore();
        var familyId = $"family-{Guid.NewGuid():N}";
        var otherFamilyId = $"family-{Guid.NewGuid():N}";
        var untouched = NewGrant(otherFamilyId);
        await store.InsertAsync(NewGrant(familyId), CancellationToken.None);
        await store.InsertAsync(untouched, CancellationToken.None);

        await store.RevokeFamilyAsync(familyId, CancellationToken.None);

        var result = await store.FindByHandleAsync(untouched.HandleHash, CancellationToken.None);
        Assert.Equal(RefreshGrantStatus.Active, result!.Status);
    }

    // ── Revocation completeness by subject, including a grant inserted mid-revoke ───────────────

    [Fact]
    public async Task RevokeBySubjectAsync_marks_every_grant_for_the_subject_as_Revoked_including_one_inserted_mid_revoke()
    {
        var store = CreateStore();
        var subject = $"subject-{Guid.NewGuid():N}";
        const int preExistingCount = 10;

        var preExisting = Enumerable.Range(0, preExistingCount)
            .Select(i => NewGrant(familyId: $"fam-{i}", subject: subject))
            .ToList();
        foreach (var grant in preExisting)
            await store.InsertAsync(grant, CancellationToken.None);

        if (!SupportsMidRevokeInsertCompleteness)
        {
            await store.RevokeBySubjectAsync(subject, CancellationToken.None);
            foreach (var grant in preExisting)
            {
                var result = await store.FindByHandleAsync(grant.HandleHash, CancellationToken.None);
                Assert.Equal(RefreshGrantStatus.Revoked, result!.Status);
            }
            return;
        }

        var midRevokeGrant = NewGrant(familyId: "fam-mid-revoke", subject: subject);
        using var insertStarted = new SemaphoreSlim(0, 1);
        using var revokeMayProceed = new SemaphoreSlim(0, 1);

        var insertTask = Task.Run(async () =>
        {
            insertStarted.Release();
            await revokeMayProceed.WaitAsync();
            await store.InsertAsync(midRevokeGrant, CancellationToken.None);
        });

        await insertStarted.WaitAsync();
        revokeMayProceed.Release();
        await Task.WhenAll(insertTask, store.RevokeBySubjectAsync(subject, CancellationToken.None).AsTask());

        foreach (var grant in preExisting.Append(midRevokeGrant))
        {
            var result = await store.FindByHandleAsync(grant.HandleHash, CancellationToken.None);
            Assert.NotNull(result);
            Assert.Equal(RefreshGrantStatus.Revoked, result!.Status);
        }
    }

    [Fact]
    public async Task RevokeBySubjectAsync_does_not_affect_grants_for_a_different_subject()
    {
        var store = CreateStore();
        var subject = $"subject-{Guid.NewGuid():N}";
        var otherSubject = $"subject-{Guid.NewGuid():N}";
        var untouched = NewGrant(familyId: "fam-untouched", subject: otherSubject);
        await store.InsertAsync(NewGrant(familyId: "fam-target", subject: subject), CancellationToken.None);
        await store.InsertAsync(untouched, CancellationToken.None);

        await store.RevokeBySubjectAsync(subject, CancellationToken.None);

        var result = await store.FindByHandleAsync(untouched.HandleHash, CancellationToken.None);
        Assert.Equal(RefreshGrantStatus.Active, result!.Status);
    }

    // ── CAS atomicity, mirroring the authorization-code store's insert-if-absent case ───────────

    [Fact]
    public async Task TryMarkConsumedAsync_exactly_one_of_many_concurrent_calls_to_the_same_handle_succeeds()
    {
        if (!SupportsAtomicConsume)
            return;

        var store = CreateStore();
        var grant = NewGrant(familyId: $"fam-{Guid.NewGuid():N}");
        await store.InsertAsync(grant, CancellationToken.None);

        const int concurrency = 50;
        using var gate = new SemaphoreSlim(0, concurrency);

        var tasks = Enumerable.Range(0, concurrency)
            .Select(_ => Task.Run(async () =>
            {
                await gate.WaitAsync();
                return await store.TryMarkConsumedAsync(grant.HandleHash, CancellationToken.None);
            }))
            .ToArray();

        gate.Release(concurrency);
        var results = await Task.WhenAll(tasks);

        // The backend's TryMarkConsumedAsync MUST be a genuine atomic CAS.
        Assert.Equal(1, results.Count(r => r));
    }

    [Fact]
    public async Task InsertAsync_then_FindByHandleAsync_round_trips_the_grant()
    {
        var store = CreateStore();
        var grant = NewGrant(familyId: $"fam-{Guid.NewGuid():N}");

        await store.InsertAsync(grant, CancellationToken.None);
        var result = await store.FindByHandleAsync(grant.HandleHash, CancellationToken.None);

        Assert.NotNull(result);
        Assert.Equal(grant.Status, result!.Status);
        Assert.Equal(grant.FamilyId, result.FamilyId);
        Assert.Equal(grant.Subject, result.Subject);
    }

    [Fact]
    public async Task FindByHandleAsync_returns_null_for_a_confirmed_absent_handle()
    {
        var store = CreateStore();

        var result = await store.FindByHandleAsync(NewKey(), CancellationToken.None);

        Assert.Null(result);
    }

    // ── Fail-closed / throws-not-swallows ────────────────────────────────────────────────────────

    /// <summary>
    /// The dangerous one: if <c>FindByHandleAsync</c> swallows a transport fault and returns
    /// <see langword="null"/>, the coordinator reads that as "confirmed absent" — on
    /// the replay path this silently defeats reuse detection (RFC 9700 §4.13).
    /// </summary>
    [Fact]
    public async Task FindByHandleAsync_propagates_a_transport_fault_instead_of_swallowing_it()
    {
        var fault = new TransportFaultException();
        var store = CreateFaultInjectedStore(fault);
        if (store is null)
            return;

        var thrown = await Assert.ThrowsAnyAsync<Exception>(
            () => store.FindByHandleAsync(NewKey(), CancellationToken.None).AsTask());
        AssertPropagatedFault(fault, thrown);
    }

    [Fact]
    public async Task InsertAsync_propagates_a_transport_fault_instead_of_swallowing_it()
    {
        var fault = new TransportFaultException();
        var store = CreateFaultInjectedStore(fault);
        if (store is null)
            return;

        var thrown = await Assert.ThrowsAnyAsync<Exception>(
            () => store.InsertAsync(NewGrant(familyId: "fam-fault"), CancellationToken.None).AsTask());
        AssertPropagatedFault(fault, thrown);
    }

    /// <summary>
    /// Also dangerous: if <c>TryMarkConsumedAsync</c> swallows a transport fault
    /// and returns <see langword="false"/>, the coordinator reads that as "CAS lost" — the same
    /// replay is then free to retry indefinitely instead of surfacing the fault, silently defeating
    /// reuse detection exactly as a swallowed <c>FindByHandleAsync</c> fault would.
    /// </summary>
    [Fact]
    public async Task TryMarkConsumedAsync_propagates_a_transport_fault_instead_of_swallowing_it()
    {
        var fault = new TransportFaultException();
        var store = CreateFaultInjectedStore(fault);
        if (store is null)
            return;

        var thrown = await Assert.ThrowsAnyAsync<Exception>(
            () => store.TryMarkConsumedAsync(NewKey(), CancellationToken.None).AsTask());
        AssertPropagatedFault(fault, thrown);
    }

    // ── Post-revoke insert completeness via IsFamilyRevokedAsync ────────────────────────────────

    /// <summary>
    /// Distinct from the mid-revoke concurrent-overlap case above: here the insert happens strictly
    /// AFTER <c>RevokeFamilyAsync</c> has already returned, not racing it. A grant inserted after a
    /// revoke need not be born <c>Revoked</c> on its own row — the consume-time gate must see the
    /// family as revoked regardless, which is exactly what
    /// <see cref="IRefreshTokenGrantStore.IsFamilyRevokedAsync"/> must report.
    /// </summary>
    [Fact]
    public async Task IsFamilyRevokedAsync_reports_revoked_for_a_grant_inserted_strictly_after_RevokeFamilyAsync_returns()
    {
        var store = CreateStore();
        var familyId = $"family-{Guid.NewGuid():N}";
        await store.InsertAsync(NewGrant(familyId), CancellationToken.None);

        await store.RevokeFamilyAsync(familyId, CancellationToken.None);

        var postRevokeGrant = NewGrant(familyId);
        await store.InsertAsync(postRevokeGrant, CancellationToken.None);

        var isRevoked = await store.IsFamilyRevokedAsync(familyId, CancellationToken.None);

        Assert.True(isRevoked);
    }

    /// <summary>
    /// The dangerous one: if <c>IsFamilyRevokedAsync</c> swallows a transport fault
    /// and returns <see langword="false"/>, the consume-time gate reads that as "not revoked" and
    /// fails open on exactly the reuse it was added to catch.
    /// </summary>
    [Fact]
    public async Task IsFamilyRevokedAsync_propagates_a_transport_fault_instead_of_swallowing_it()
    {
        var fault = new TransportFaultException();
        var store = CreateFaultInjectedStore(fault);
        if (store is null)
            return;

        var thrown = await Assert.ThrowsAnyAsync<Exception>(
            () => store.IsFamilyRevokedAsync("fam-fault", CancellationToken.None).AsTask());
        AssertPropagatedFault(fault, thrown);
    }

    // ── Backend-level precondition for the revocation sentinel ──────────────────────────────────
    //
    // "RevokeFamilyAsync on a zero-row family, then insert a grant, then assert
    // IsFamilyRevokedAsync reports it revoked" describes the coordinator's *composed* behaviour,
    // not something either backend's IRefreshTokenGrantStore implementation does on its own: the
    // coordinator's RevokeFamilyAsync constructs a Revoked-status sentinel row itself and inserts
    // it via InsertAsync — the backend's own RevokeFamilyAsync method (UPDATE ... WHERE family_id
    // = @f) still matches nothing on a zero-row family and is unchanged. Exercising that composed
    // scenario against a bare IRefreshTokenGrantStore would therefore just prove that
    // RevokeFamilyAsync-on-empty-family is a no-op, which is correct backend behaviour, not a
    // regression — asserting IsFamilyRevokedAsync afterwards would legitimately return false at
    // this layer, so a literal port of that scenario would be testing the wrong layer.
    //
    // What the coordinator's behaviour DOES depend on, and what the interface's InsertAsync
    // contract has never explicitly stated one way or the other, is that InsertAsync tolerates a
    // grant born Revoked with no prior Active row for its family, and that IsFamilyRevokedAsync
    // sees it. A hypothetical third-party backend that (wrongly) assumed InsertAsync is only ever
    // called with Active status — e.g. one that derives "family exists" from "an Active row has
    // ever been written" rather than from row presence — would break the sentinel technique
    // silently. That is the genuine, non-redundant assertion about the IRefreshTokenGrantStore
    // contract covered here.
    [Fact]
    public async Task InsertAsync_accepts_a_grant_born_Revoked_with_no_prior_row_and_IsFamilyRevokedAsync_reports_it()
    {
        var store = CreateStore();
        var familyId = $"family-{Guid.NewGuid():N}";
        var revokedFromBirth = NewGrant(familyId, status: RefreshGrantStatus.Revoked);

        await store.InsertAsync(revokedFromBirth, CancellationToken.None);

        var stored = await store.FindByHandleAsync(revokedFromBirth.HandleHash, CancellationToken.None);
        Assert.Equal(RefreshGrantStatus.Revoked, stored!.Status);

        var isRevoked = await store.IsFamilyRevokedAsync(familyId, CancellationToken.None);
        Assert.True(isRevoked);
    }

    /// <summary>
    /// Accepts either the raw fault propagating unwrapped (native exceptions may propagate
    /// freely; the coordinator's Guarded wrapper maps them) or
    /// the fault wrapped as <see cref="ZeeKayDaStoreException"/> with the original fault preserved
    /// as <see cref="Exception.InnerException"/> (a backend that wraps its own transport faults
    /// before the coordinator ever sees them). What this test forbids either way is the fault
    /// being swallowed and the call returning as if nothing happened.
    /// </summary>
    private static void AssertPropagatedFault(Exception fault, Exception thrown)
    {
        if (ReferenceEquals(thrown, fault))
            return;

        Assert.IsType<ZeeKayDaStoreException>(thrown);
        Assert.Same(fault, thrown.InnerException);
    }

    /// <summary>A distinct, clearly-fake exception type used to inject transport faults, so these
    /// tests can never be confused with a real backend exception type.</summary>
    private sealed class TransportFaultException : Exception;
}
