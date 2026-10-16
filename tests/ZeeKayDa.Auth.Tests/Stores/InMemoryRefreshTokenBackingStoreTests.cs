using Microsoft.Extensions.Time.Testing;
using ZeeKayDa.Auth.Stores;

namespace ZeeKayDa.Auth.Tests.Stores;

/// <summary>
/// Adapter-level tests for <see cref="InMemoryRefreshTokenBackingStore"/>: insert,
/// find, the CAS invariant, and family/subject revocation. No hashing, encryption, expiry, or
/// outcome-selection knowledge belongs here — that is the coordinator's job
/// (<c>RefreshTokenStoreTests</c>).
/// </summary>
public sealed class InMemoryRefreshTokenBackingStoreTests
{
    private static readonly DateTimeOffset FarFuture = new(2099, 1, 1, 0, 0, 0, TimeSpan.Zero);
    private static readonly DateTimeOffset Now = new(2026, 10, 16, 12, 0, 0, TimeSpan.Zero);
    private static readonly TimeSpan Skew = TimeSpan.FromSeconds(30);

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
        var store = InMemoryStores.RefreshTokens();
        var grant = BuildGrant();

        await store.InsertAsync(grant, CancellationToken.None);
        var result = await store.FindByHandleAsync(grant.HandleHash, CancellationToken.None);

        result.Should().BeEquivalentTo(grant);
    }

    [Fact]
    public async Task FindByHandleAsync_returns_null_for_a_confirmed_absent_handle()
    {
        var store = InMemoryStores.RefreshTokens();

        var result = await store.FindByHandleAsync(NewKey(), CancellationToken.None);

        result.Should().BeNull();
    }

    [Fact]
    public async Task InsertAsync_throws_ZeeKayDaStoreException_on_handle_collision()
    {
        var store = InMemoryStores.RefreshTokens();
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
        var store = InMemoryStores.RefreshTokens();
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
        var store = InMemoryStores.RefreshTokens();
        var grant = BuildGrant(status: RefreshGrantStatus.Consumed);
        await store.InsertAsync(grant, CancellationToken.None);

        var won = await store.TryMarkConsumedAsync(grant.HandleHash, CancellationToken.None);

        won.Should().BeFalse();
    }

    [Fact]
    public async Task TryMarkConsumedAsync_returns_false_for_a_Revoked_grant_and_does_not_change_its_status()
    {
        var store = InMemoryStores.RefreshTokens();
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
        var store = InMemoryStores.RefreshTokens();

        var won = await store.TryMarkConsumedAsync(NewKey(), CancellationToken.None);

        won.Should().BeFalse();
    }

    [Fact]
    public async Task TryMarkConsumedAsync_exactly_one_of_many_concurrent_calls_returns_true()
    {
        var store = InMemoryStores.RefreshTokens();
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
        var store = InMemoryStores.RefreshTokens();
        const string familyId = "family-to-revoke";
        var g1 = BuildGrant(familyId: familyId);
        var g2 = BuildGrant(familyId: familyId);
        var g3 = BuildGrant(familyId: "other-family");
        await store.InsertAsync(g1, CancellationToken.None);
        await store.InsertAsync(g2, CancellationToken.None);
        await store.InsertAsync(g3, CancellationToken.None);

        await store.RevokeFamilyAsync(familyId, FarFuture, CancellationToken.None);

        (await store.FindByHandleAsync(g1.HandleHash, CancellationToken.None))!.Status.Should().Be(RefreshGrantStatus.Revoked);
        (await store.FindByHandleAsync(g2.HandleHash, CancellationToken.None))!.Status.Should().Be(RefreshGrantStatus.Revoked);
        (await store.FindByHandleAsync(g3.HandleHash, CancellationToken.None))!.Status.Should().Be(RefreshGrantStatus.Active,
            because: "revoking a different family must not affect this grant");
    }

    [Fact]
    public async Task RevokeFamilyAsync_does_not_overwrite_a_Consumed_status_back_to_Active()
    {
        // Mark-don't-delete: a consumed tombstone must remain a terminal state, not regress.
        var store = InMemoryStores.RefreshTokens();
        const string familyId = "family-consumed-then-revoked";
        var grant = BuildGrant(familyId: familyId);
        await store.InsertAsync(grant, CancellationToken.None);
        await store.TryMarkConsumedAsync(grant.HandleHash, CancellationToken.None);

        await store.RevokeFamilyAsync(familyId, FarFuture, CancellationToken.None);

        var result = await store.FindByHandleAsync(grant.HandleHash, CancellationToken.None);
        result!.Status.Should().Be(RefreshGrantStatus.Revoked,
            because: "revocation is a terminal override even over a Consumed tombstone — both are terminal states");
    }

    [Fact]
    public async Task RevokeFamilyAsync_with_unknown_family_id_does_not_throw()
    {
        var store = InMemoryStores.RefreshTokens();

        var act = async () => await store.RevokeFamilyAsync("completely-unknown-family", FarFuture, CancellationToken.None);

        await act.Should().NotThrowAsync();
    }

    [Fact]
    public async Task RevokeFamilyAsync_is_idempotent()
    {
        var store = InMemoryStores.RefreshTokens();
        const string familyId = "idempotent-family";
        await store.InsertAsync(BuildGrant(familyId: familyId), CancellationToken.None);

        await store.RevokeFamilyAsync(familyId, FarFuture, CancellationToken.None);
        var act = async () => await store.RevokeFamilyAsync(familyId, FarFuture, CancellationToken.None);

        await act.Should().NotThrowAsync();
    }

    // ── RevokeBySubjectAsync ──────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task RevokeBySubjectAsync_marks_every_grant_for_the_subject_as_Revoked_across_families()
    {
        var store = InMemoryStores.RefreshTokens();
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
        var store = InMemoryStores.RefreshTokens();

        var act = async () => await store.RevokeBySubjectAsync("unknown-subject", CancellationToken.None);

        await act.Should().NotThrowAsync();
    }

    // ── IsFamilyRevokedAsync (issue #386) ────────────────────────────────────────────────────────────

    [Fact]
    public async Task IsFamilyRevokedAsync_returns_true_once_the_family_is_revoked()
    {
        var store = InMemoryStores.RefreshTokens();
        const string familyId = "family-revoked";
        var grant = BuildGrant(familyId: familyId);
        await store.InsertAsync(grant, CancellationToken.None);
        await store.RevokeFamilyAsync(familyId, FarFuture, CancellationToken.None);

        var result = await store.IsFamilyRevokedAsync(familyId, CancellationToken.None);

        result.Should().BeTrue();
    }

    [Fact]
    public async Task IsFamilyRevokedAsync_returns_true_for_a_successor_inserted_strictly_after_the_revoke()
    {
        // The exact issue #386 scenario: RT0 gets revoked, RT1 is inserted afterwards still Active.
        var store = InMemoryStores.RefreshTokens();
        const string familyId = "family-post-revoke-insert";
        var rt0 = BuildGrant(familyId: familyId);
        await store.InsertAsync(rt0, CancellationToken.None);
        await store.RevokeFamilyAsync(familyId, FarFuture, CancellationToken.None);

        var rt1 = BuildGrant(familyId: familyId);
        await store.InsertAsync(rt1, CancellationToken.None);

        var result = await store.IsFamilyRevokedAsync(familyId, CancellationToken.None);

        result.Should().BeTrue(because: "the family reads revoked even though rt1's own row is still Active");
        (await store.FindByHandleAsync(rt1.HandleHash, CancellationToken.None))!.Status
            .Should().Be(RefreshGrantStatus.Active, because: "InsertAsync is unchanged and never itself decides Active vs Revoked");
    }

    [Fact]
    public async Task IsFamilyRevokedAsync_returns_false_when_no_grant_in_the_family_is_Revoked()
    {
        var store = InMemoryStores.RefreshTokens();
        const string familyId = "family-live";
        await store.InsertAsync(BuildGrant(familyId: familyId), CancellationToken.None);

        var result = await store.IsFamilyRevokedAsync(familyId, CancellationToken.None);

        result.Should().BeFalse();
    }

    [Fact]
    public async Task IsFamilyRevokedAsync_returns_false_for_an_unknown_family_id()
    {
        var store = InMemoryStores.RefreshTokens();

        var result = await store.IsFamilyRevokedAsync("completely-unknown-family", CancellationToken.None);

        result.Should().BeFalse();
    }

    [Fact]
    public async Task IsFamilyRevokedAsync_ignores_the_revocation_of_a_different_family()
    {
        var store = InMemoryStores.RefreshTokens();
        await store.RevokeFamilyAsync("other-family", FarFuture, CancellationToken.None);
        const string familyId = "family-not-revoked";
        await store.InsertAsync(BuildGrant(familyId: familyId), CancellationToken.None);

        var result = await store.IsFamilyRevokedAsync(familyId, CancellationToken.None);

        result.Should().BeFalse();
    }

    [Fact]
    public async Task IsFamilyRevokedAsync_answers_from_the_revocation_record_not_from_revoked_rows()
    {
        var store = InMemoryStores.RefreshTokens();
        const string familyId = "family-rows-revoked-by-subject";
        await store.InsertAsync(BuildGrant(familyId: familyId, subject: "user-gone"), CancellationToken.None);
        await store.RevokeBySubjectAsync("user-gone", CancellationToken.None);

        var result = await store.IsFamilyRevokedAsync(familyId, CancellationToken.None);

        result.Should().BeFalse(because: "only RevokeFamilyAsync records a family as revoked");
    }

    [Fact]
    public async Task IsFamilyRevokedAsync_throws_ArgumentNullException_for_null_familyId()
    {
        var store = InMemoryStores.RefreshTokens();

        var act = async () => await store.IsFamilyRevokedAsync(null!, CancellationToken.None);

        await act.Should().ThrowAsync<ArgumentNullException>();
    }

    // ── Argument guards ───────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task InsertAsync_throws_ArgumentNullException_for_null_grant()
    {
        var store = InMemoryStores.RefreshTokens();

        var act = async () => await store.InsertAsync(null!, CancellationToken.None);

        await act.Should().ThrowAsync<ArgumentNullException>();
    }

    [Fact]
    public async Task RevokeFamilyAsync_throws_ArgumentNullException_for_null_familyId()
    {
        var store = InMemoryStores.RefreshTokens();

        var act = async () => await store.RevokeFamilyAsync(null!, FarFuture, CancellationToken.None);

        await act.Should().ThrowAsync<ArgumentNullException>();
    }

    [Fact]
    public async Task RevokeBySubjectAsync_throws_ArgumentNullException_for_null_subject()
    {
        var store = InMemoryStores.RefreshTokens();

        var act = async () => await store.RevokeBySubjectAsync(null!, CancellationToken.None);

        await act.Should().ThrowAsync<ArgumentNullException>();
    }

    // ── Cancellation ──────────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task InsertAsync_respects_pre_cancelled_CancellationToken()
    {
        var store = InMemoryStores.RefreshTokens();
        using var cts = new CancellationTokenSource();
        cts.Cancel();

        var act = async () => await store.InsertAsync(BuildGrant(), cts.Token);

        await act.Should().ThrowAsync<OperationCanceledException>();
    }

    // ── Eviction ──────────────────────────────────────────────────────────────────────────────────

    private static InMemoryRefreshTokenBackingStore StoreAt(FakeTimeProvider time) =>
        InMemoryStores.RefreshTokens(time, new AuthorizationServerOptions { ClockSkewTolerance = Skew });

    [Fact]
    public async Task InsertAsync_removes_a_grant_whose_family_is_past_its_absolute_expiry_by_more_than_the_clock_skew_tolerance()
    {
        var time = new FakeTimeProvider(Now);
        var store = StoreAt(time);
        var expired = BuildGrant() with { FamilyAbsoluteExpiry = Now.AddHours(1), ExpiresAt = Now.AddHours(1) };
        await store.InsertAsync(expired, CancellationToken.None);
        time.SetUtcNow(Now.AddHours(1) + Skew + TimeSpan.FromSeconds(1));

        await store.InsertAsync(BuildGrant(familyId: "family-2"), CancellationToken.None);

        store.Count.Should().Be(1, "a development host must not hold every refresh token it ever issued");
        (await store.FindByHandleAsync(expired.HandleHash, CancellationToken.None)).Should().BeNull();
    }

    [Fact]
    public async Task InsertAsync_keeps_a_consumed_grant_past_its_own_expiry_while_its_family_can_still_be_live()
    {
        // Reuse detection reads the consumed row: forgetting it at the token's own expiry would let a
        // replay of a rotated token pass unnoticed while its successor is still live.
        var time = new FakeTimeProvider(Now);
        var store = StoreAt(time);
        var consumed = BuildGrant(status: RefreshGrantStatus.Consumed) with { ExpiresAt = Now.AddMinutes(10) };
        await store.InsertAsync(consumed, CancellationToken.None);
        time.SetUtcNow(Now.AddDays(1));

        await store.InsertAsync(BuildGrant(familyId: "family-2"), CancellationToken.None);

        (await store.FindByHandleAsync(consumed.HandleHash, CancellationToken.None)).Should().NotBeNull();
    }

    [Fact]
    public async Task InsertAsync_keeps_a_grant_within_the_clock_skew_tolerance_of_its_family_absolute_expiry()
    {
        var time = new FakeTimeProvider(Now);
        var store = StoreAt(time);
        var grant = BuildGrant() with { FamilyAbsoluteExpiry = Now.AddHours(1), ExpiresAt = Now.AddHours(1) };
        await store.InsertAsync(grant, CancellationToken.None);
        time.SetUtcNow(Now.AddHours(1) + Skew);

        await store.InsertAsync(BuildGrant(familyId: "family-2"), CancellationToken.None);

        (await store.FindByHandleAsync(grant.HandleHash, CancellationToken.None)).Should().NotBeNull();
    }

    [Fact]
    public async Task InsertAsync_forgets_a_revoked_family_once_its_rememberUntil_has_passed()
    {
        var time = new FakeTimeProvider(Now);
        var store = StoreAt(time);
        await store.RevokeFamilyAsync("family-1", Now.AddHours(1), CancellationToken.None);
        time.SetUtcNow(Now.AddHours(1).AddSeconds(1));

        await store.InsertAsync(BuildGrant(familyId: "family-2"), CancellationToken.None);

        (await store.IsFamilyRevokedAsync("family-1", CancellationToken.None)).Should().BeFalse();
    }

    [Fact]
    public async Task InsertAsync_keeps_a_revoked_family_until_its_rememberUntil()
    {
        var time = new FakeTimeProvider(Now);
        var store = StoreAt(time);
        await store.RevokeFamilyAsync("family-1", Now.AddHours(1), CancellationToken.None);
        time.SetUtcNow(Now.AddHours(1));

        await store.InsertAsync(BuildGrant(familyId: "family-2"), CancellationToken.None);

        (await store.IsFamilyRevokedAsync("family-1", CancellationToken.None)).Should().BeTrue();
    }

    [Fact]
    public async Task InsertAsync_keeps_a_revoked_family_until_the_latest_rememberUntil_any_revoke_asked_for()
    {
        var time = new FakeTimeProvider(Now);
        var store = StoreAt(time);
        await store.RevokeFamilyAsync("family-1", Now.AddHours(2), CancellationToken.None);
        await store.RevokeFamilyAsync("family-1", Now.AddHours(1), CancellationToken.None);
        time.SetUtcNow(Now.AddHours(1).AddMinutes(30));

        await store.InsertAsync(BuildGrant(familyId: "family-2"), CancellationToken.None);

        (await store.IsFamilyRevokedAsync("family-1", CancellationToken.None)).Should().BeTrue();
    }
}
