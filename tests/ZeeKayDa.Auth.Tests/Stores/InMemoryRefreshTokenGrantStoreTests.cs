using ZeeKayDa.Auth.Stores;

namespace ZeeKayDa.Auth.Tests.Stores;

/// <summary>
/// Adapter-level tests for <see cref="InMemoryRefreshTokenGrantStore"/> (ADR 0014 §1/§3): insert,
/// find, the CAS invariant, and family/subject revocation. No hashing, encryption, expiry, or
/// outcome-selection knowledge belongs here — that is the coordinator's job
/// (<c>RefreshTokenStoreTests</c>).
/// </summary>
public sealed class InMemoryRefreshTokenGrantStoreTests
{
    private static readonly DateTimeOffset FarFuture = new(2099, 1, 1, 0, 0, 0, TimeSpan.Zero);

    private static RefreshTokenGrant BuildGrant(
        StoreKey? handleHash = null,
        string familyId = "family-1",
        string subject = "user-1",
        string clientId = "client-a",
        RefreshGrantStatus status = RefreshGrantStatus.Active) =>
        new()
        {
            HandleHash = handleHash ?? NewKey(),
            FamilyId = familyId,
            Subject = subject,
            ClientId = clientId,
            FamilyAbsoluteExpiry = FarFuture,
            ExpiresAt = FarFuture,
            Status = status,
            ProtectedPayload = new byte[] { 1, 2, 3 },
        };

    private static StoreKey NewKey() => new($"grant-{Guid.NewGuid():N}");

    // ── InsertAsync / FindByHandleAsync round-trip ────────────────────────────────────────────────

    [Fact]
    public async Task InsertAsync_then_FindByHandleAsync_round_trips_the_grant()
    {
        var store = new InMemoryRefreshTokenGrantStore();
        var grant = BuildGrant();

        await store.InsertAsync(grant, CancellationToken.None);
        var result = await store.FindByHandleAsync(grant.HandleHash, CancellationToken.None);

        result.Should().BeEquivalentTo(grant);
    }

    [Fact]
    public async Task FindByHandleAsync_returns_null_for_a_confirmed_absent_handle()
    {
        var store = new InMemoryRefreshTokenGrantStore();

        var result = await store.FindByHandleAsync(NewKey(), CancellationToken.None);

        result.Should().BeNull();
    }

    [Fact]
    public async Task InsertAsync_throws_ZeeKayDaStoreException_on_handle_collision()
    {
        var store = new InMemoryRefreshTokenGrantStore();
        var key = NewKey();
        await store.InsertAsync(BuildGrant(handleHash: key), CancellationToken.None);

        var act = async () => await store.InsertAsync(BuildGrant(handleHash: key), CancellationToken.None);

        await act.Should().ThrowAsync<ZeeKayDaStoreException>(
            because: "handles are 256-bit random, so a colliding insert is a genuine anomaly, not a normal path");
    }

    // ── TryMarkConsumedAsync: THE atomic invariant ────────────────────────────────────────────────

    [Fact]
    public async Task TryMarkConsumedAsync_returns_true_and_transitions_an_Active_grant_to_Consumed()
    {
        var store = new InMemoryRefreshTokenGrantStore();
        var grant = BuildGrant(status: RefreshGrantStatus.Active);
        await store.InsertAsync(grant, CancellationToken.None);

        var won = await store.TryMarkConsumedAsync(grant.HandleHash, CancellationToken.None);

        won.Should().BeTrue();
        (await store.FindByHandleAsync(grant.HandleHash, CancellationToken.None))!.Status
            .Should().Be(RefreshGrantStatus.Consumed);
    }

    [Fact]
    public async Task TryMarkConsumedAsync_returns_false_for_an_already_Consumed_grant()
    {
        var store = new InMemoryRefreshTokenGrantStore();
        var grant = BuildGrant(status: RefreshGrantStatus.Consumed);
        await store.InsertAsync(grant, CancellationToken.None);

        var won = await store.TryMarkConsumedAsync(grant.HandleHash, CancellationToken.None);

        won.Should().BeFalse();
    }

    [Fact]
    public async Task TryMarkConsumedAsync_returns_false_for_a_Revoked_grant_and_does_not_change_its_status()
    {
        var store = new InMemoryRefreshTokenGrantStore();
        var grant = BuildGrant(status: RefreshGrantStatus.Revoked);
        await store.InsertAsync(grant, CancellationToken.None);

        var won = await store.TryMarkConsumedAsync(grant.HandleHash, CancellationToken.None);

        won.Should().BeFalse();
        (await store.FindByHandleAsync(grant.HandleHash, CancellationToken.None))!.Status
            .Should().Be(RefreshGrantStatus.Revoked);
    }

    [Fact]
    public async Task TryMarkConsumedAsync_returns_false_for_an_absent_handle()
    {
        var store = new InMemoryRefreshTokenGrantStore();

        var won = await store.TryMarkConsumedAsync(NewKey(), CancellationToken.None);

        won.Should().BeFalse();
    }

    [Fact]
    public async Task TryMarkConsumedAsync_exactly_one_of_many_concurrent_calls_returns_true()
    {
        var store = new InMemoryRefreshTokenGrantStore();
        var grant = BuildGrant();
        await store.InsertAsync(grant, CancellationToken.None);

        const int concurrency = 100;
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

        results.Count(won => won).Should().Be(1);
    }

    // ── RevokeFamilyAsync ─────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task RevokeFamilyAsync_marks_every_grant_in_the_family_as_Revoked()
    {
        var store = new InMemoryRefreshTokenGrantStore();
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
        (await store.FindByHandleAsync(g3.HandleHash, CancellationToken.None))!.Status.Should().Be(RefreshGrantStatus.Active,
            because: "revoking a different family must not affect this grant");
    }

    [Fact]
    public async Task RevokeFamilyAsync_does_not_overwrite_a_Consumed_status_back_to_Active()
    {
        // Mark-don't-delete: a consumed tombstone must remain a terminal state, not regress.
        var store = new InMemoryRefreshTokenGrantStore();
        const string familyId = "family-consumed-then-revoked";
        var grant = BuildGrant(familyId: familyId);
        await store.InsertAsync(grant, CancellationToken.None);
        await store.TryMarkConsumedAsync(grant.HandleHash, CancellationToken.None);

        await store.RevokeFamilyAsync(familyId, CancellationToken.None);

        var result = await store.FindByHandleAsync(grant.HandleHash, CancellationToken.None);
        result!.Status.Should().Be(RefreshGrantStatus.Revoked,
            because: "revocation is a terminal override even over a Consumed tombstone — both are terminal states");
    }

    [Fact]
    public async Task RevokeFamilyAsync_with_unknown_family_id_does_not_throw()
    {
        var store = new InMemoryRefreshTokenGrantStore();

        var act = async () => await store.RevokeFamilyAsync("completely-unknown-family", CancellationToken.None);

        await act.Should().NotThrowAsync();
    }

    [Fact]
    public async Task RevokeFamilyAsync_is_idempotent()
    {
        var store = new InMemoryRefreshTokenGrantStore();
        const string familyId = "idempotent-family";
        await store.InsertAsync(BuildGrant(familyId: familyId), CancellationToken.None);

        await store.RevokeFamilyAsync(familyId, CancellationToken.None);
        var act = async () => await store.RevokeFamilyAsync(familyId, CancellationToken.None);

        await act.Should().NotThrowAsync();
    }

    // ── RevokeBySubjectAsync ──────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task RevokeBySubjectAsync_marks_every_grant_for_the_subject_as_Revoked_across_families()
    {
        var store = new InMemoryRefreshTokenGrantStore();
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

    [Fact]
    public async Task RevokeBySubjectAsync_with_unknown_subject_does_not_throw()
    {
        var store = new InMemoryRefreshTokenGrantStore();

        var act = async () => await store.RevokeBySubjectAsync("unknown-subject", CancellationToken.None);

        await act.Should().NotThrowAsync();
    }

    // ── Argument guards ───────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task InsertAsync_throws_ArgumentNullException_for_null_grant()
    {
        var store = new InMemoryRefreshTokenGrantStore();

        var act = async () => await store.InsertAsync(null!, CancellationToken.None);

        await act.Should().ThrowAsync<ArgumentNullException>();
    }

    [Fact]
    public async Task RevokeFamilyAsync_throws_ArgumentNullException_for_null_familyId()
    {
        var store = new InMemoryRefreshTokenGrantStore();

        var act = async () => await store.RevokeFamilyAsync(null!, CancellationToken.None);

        await act.Should().ThrowAsync<ArgumentNullException>();
    }

    [Fact]
    public async Task RevokeBySubjectAsync_throws_ArgumentNullException_for_null_subject()
    {
        var store = new InMemoryRefreshTokenGrantStore();

        var act = async () => await store.RevokeBySubjectAsync(null!, CancellationToken.None);

        await act.Should().ThrowAsync<ArgumentNullException>();
    }

    // ── Cancellation ──────────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task InsertAsync_respects_pre_cancelled_CancellationToken()
    {
        var store = new InMemoryRefreshTokenGrantStore();
        using var cts = new CancellationTokenSource();
        cts.Cancel();

        var act = async () => await store.InsertAsync(BuildGrant(), cts.Token);

        await act.Should().ThrowAsync<OperationCanceledException>();
    }
}
