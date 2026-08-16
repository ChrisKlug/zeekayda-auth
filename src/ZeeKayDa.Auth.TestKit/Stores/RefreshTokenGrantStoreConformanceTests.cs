using ZeeKayDa.Auth.Stores;

namespace ZeeKayDa.Auth.TestKit.Stores;

/// <summary>
/// Ready-to-derive conformance kit for <see cref="IRefreshTokenGrantStore"/> implementers. Running
/// this against a production backend is a MUST: it exercises invariants the CLR cannot verify
/// structurally — revocation completeness by family and by subject (including a grant inserted
/// mid-revoke), CAS atomicity on <see cref="IRefreshTokenGrantStore.TryMarkConsumedAsync"/>, and
/// fail-closed fault propagation on the store's read and consume paths.
/// </summary>
/// <remarks>
/// Reference <c>ZeeKayDa.Auth.TestKit</c> from your own test project, derive this class, and
/// implement <see cref="CreateStore"/> to return your <see cref="IRefreshTokenGrantStore"/>. You
/// do not need to construct a <see cref="StoreKey"/> yourself — this kit builds one internally.
/// </remarks>
public abstract class RefreshTokenGrantStoreConformanceTests
{
    private static readonly DateTimeOffset FarFuture = new(2099, 1, 1, 0, 0, 0, TimeSpan.Zero);

    /// <summary>Creates a fresh, empty store instance under test.</summary>
    protected abstract IRefreshTokenGrantStore CreateStore();

    /// <summary>
    /// Override to <see langword="false"/> only for a non-atomic dev/test backend (e.g. the
    /// first-party <c>DistributedCacheRefreshTokenGrantStore</c>). Production backends MUST
    /// support atomic compare-and-set.
    /// </summary>
    protected virtual bool SupportsAtomicConsume => true;

    /// <summary>
    /// Override to <see langword="false"/> only for a non-transactional secondary-index backend
    /// whose family/subject revocation cannot be proven complete against a grant inserted
    /// concurrently with the revoke call. Production backends MUST support this.
    /// </summary>
    protected virtual bool SupportsMidRevokeInsertCompleteness => true;

    /// <summary>
    /// Override to provide a store whose underlying transport always throws
    /// <paramref name="fault"/>, proving fault propagation is not swallowed. Return
    /// <see langword="null"/> if the backend has no injectable failure point — the fault-injection
    /// tests are then skipped for that subclass.
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
    /// <c>RevokeFamilyAsync</c> must revoke EVERY grant in the family, not just
    /// <see cref="RefreshGrantStatus.Active"/> ones, and calling it twice must be a safe no-op.
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
    /// If <c>FindByHandleAsync</c> swallows a transport fault and returns <see langword="null"/>,
    /// the coordinator reads that as "confirmed absent", silently defeating reuse detection.
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
    /// If <c>TryMarkConsumedAsync</c> swallows a transport fault and returns
    /// <see langword="false"/>, the coordinator reads that as "CAS lost" and the same replay can
    /// retry indefinitely instead of surfacing the fault.
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
    /// A grant inserted strictly after <c>RevokeFamilyAsync</c> returns need not be born
    /// <c>Revoked</c> on its own row — the consume-time gate must still see the family as revoked,
    /// which is what <see cref="IRefreshTokenGrantStore.IsFamilyRevokedAsync"/> must report.
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
    /// If <c>IsFamilyRevokedAsync</c> swallows a transport fault and returns
    /// <see langword="false"/>, the consume-time gate fails open on the reuse it exists to catch.
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
    // The coordinator's revoke-on-empty-family sentinel technique relies on InsertAsync accepting
    // a grant born Revoked with no prior row for its family, and IsFamilyRevokedAsync then seeing
    // it. A backend that (wrongly) infers "family exists" from "an Active row was ever written"
    // rather than from row presence would break this silently — that is what this test guards.
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
    /// Accepts the raw fault propagating unwrapped, or wrapped as
    /// <see cref="ZeeKayDaStoreException"/> with the original preserved as
    /// <see cref="Exception.InnerException"/>. Either way, the fault must not be swallowed.
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
