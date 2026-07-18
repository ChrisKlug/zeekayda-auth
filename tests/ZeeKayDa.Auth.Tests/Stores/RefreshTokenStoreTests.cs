using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Time.Testing;
using ZeeKayDa.Auth.Stores;

namespace ZeeKayDa.Auth.Tests.Stores;

/// <summary>
/// Tests for the <c>RefreshTokenStore</c> framework coordinator (ADR 0014 §4). Covers the
/// cleartext-first decision tree, the CAS pivot, the lost-race re-read, the clamp arithmetic
/// (§5), and the single <c>Unprotect</c> catch site (§7) — wired over
/// <see cref="InMemoryRefreshTokenGrantStore"/> for round-trip tests and a fake
/// <see cref="IRefreshTokenGrantStore"/> where isolation of a specific decision path is needed.
/// </summary>
public sealed class RefreshTokenStoreTests
{
    private static readonly DateTimeOffset FarFuture = new(2099, 1, 1, 0, 0, 0, TimeSpan.Zero);

    private static RefreshTokenStore CreateStore(
        IRefreshTokenGrantStore? grantStore = null,
        IDataProtectionProvider? dp = null,
        AuthorizationServerOptions? serverOptions = null,
        TimeProvider? timeProvider = null)
        => new(
            grantStore ?? new InMemoryRefreshTokenGrantStore(),
            dp ?? new EphemeralDataProtectionProvider(),
            new OptionsWrapper<AuthorizationServerOptions>(serverOptions ?? new AuthorizationServerOptions()),
            timeProvider ?? TimeProvider.System);

    private static RefreshTokenEntry BuildEntry(
        string clientId = "client-a",
        string familyId = "family-1",
        string sub = "user-1",
        DateTimeOffset? issuedAt = null,
        DateTimeOffset? expiresAt = null,
        DateTimeOffset? familyAbsoluteExpiry = null,
        string? previousTokenHandleHash = null) =>
        new()
        {
            FamilyId = familyId,
            ClientId = clientId,
            Sub = sub,
            Scope = ["openid", "profile"],
            SsoSessionId = "session-1",
            IssuedAt = issuedAt ?? DateTimeOffset.UtcNow,
            ExpiresAt = expiresAt ?? FarFuture,
            FamilyAbsoluteExpiry = familyAbsoluteExpiry ?? FarFuture,
            PreviousTokenHandleHash = previousTokenHandleHash,
        };

    // ── Constructor guards ────────────────────────────────────────────────────────────────────────

    [Fact]
    public void Constructor_throws_ArgumentNullException_for_null_grantStore()
    {
        var act = () => new RefreshTokenStore(
            null!,
            new EphemeralDataProtectionProvider(),
            new OptionsWrapper<AuthorizationServerOptions>(new AuthorizationServerOptions()),
            TimeProvider.System);

        act.Should().Throw<ArgumentNullException>();
    }

    [Fact]
    public void Constructor_throws_ArgumentNullException_for_null_dataProtectionProvider()
    {
        var act = () => new RefreshTokenStore(
            new InMemoryRefreshTokenGrantStore(),
            null!,
            new OptionsWrapper<AuthorizationServerOptions>(new AuthorizationServerOptions()),
            TimeProvider.System);

        act.Should().Throw<ArgumentNullException>();
    }

    [Fact]
    public void Constructor_throws_ArgumentNullException_for_null_serverOptions()
    {
        var act = () => new RefreshTokenStore(
            new InMemoryRefreshTokenGrantStore(),
            new EphemeralDataProtectionProvider(),
            null!,
            TimeProvider.System);

        act.Should().Throw<ArgumentNullException>();
    }

    [Fact]
    public void Constructor_throws_ArgumentNullException_for_null_timeProvider()
    {
        var act = () => new RefreshTokenStore(
            new InMemoryRefreshTokenGrantStore(),
            new EphemeralDataProtectionProvider(),
            new OptionsWrapper<AuthorizationServerOptions>(new AuthorizationServerOptions()),
            null!);

        act.Should().Throw<ArgumentNullException>();
    }

    // ── Happy path ────────────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task StoreAsync_then_TryConsumeAsync_with_correct_client_returns_Consumed()
    {
        var store = CreateStore();
        const string handle = "valid-handle";

        await store.StoreAsync(handle, BuildEntry(clientId: "client-a"), CancellationToken.None);
        var outcome = await store.TryConsumeAsync(handle, "client-a", CancellationToken.None);

        outcome.Should().BeOfType<RefreshTokenConsumptionResult.Consumed>();
    }

    [Fact]
    public async Task TryConsumeAsync_Consumed_entry_matches_stored_entry()
    {
        // The §5 clamp is applied to the encrypted entry before it is protected, so every field
        // round-trips verbatim EXCEPT ExpiresAt, which reflects the clamped value actually
        // enforced — never the caller's original, possibly-larger ExpiresAt (fam-roundtrip's
        // FamilyAbsoluteExpiry is FarFuture, so RefreshTokenLifetime is the binding bound here).
        var store = CreateStore();
        const string handle = "round-trip-handle";
        var entry = BuildEntry(clientId: "client-a", familyId: "fam-roundtrip");

        var before = DateTimeOffset.UtcNow;
        await store.StoreAsync(handle, entry, CancellationToken.None);
        var outcome = await store.TryConsumeAsync(handle, "client-a", CancellationToken.None);

        var consumed = outcome.Should().BeOfType<RefreshTokenConsumptionResult.Consumed>().Subject;
        consumed.Entry.Should().BeEquivalentTo(entry,
            options => options.Excluding(e => e.ExpiresAt),
            because: "every field of the caller-supplied entry except ExpiresAt round-trips verbatim");
        consumed.Entry.ExpiresAt.Should().BeCloseTo(
            before + new AuthorizationServerOptions().TokenEndpoint.RefreshTokenLifetime, TimeSpan.FromSeconds(5),
            because: "the returned entry's ExpiresAt must match the clamped value the coordinator actually enforces");
    }

    [Fact]
    public async Task FindAsync_returns_stored_entry_when_all_checks_pass()
    {
        // See TryConsumeAsync_Consumed_entry_matches_stored_entry above: ExpiresAt reflects the
        // §5-clamped value actually enforced, not the caller's original, possibly-larger ExpiresAt.
        var store = CreateStore();
        const string handle = "find-round-trip";
        var entry = BuildEntry(clientId: "client-a", familyId: "fam-1");

        var before = DateTimeOffset.UtcNow;
        await store.StoreAsync(handle, entry, CancellationToken.None);
        var result = await store.FindAsync(handle, CancellationToken.None);

        result.Should().NotBeNull(because: "a stored, unexpired, unconsumed entry must be found");
        result.Should().BeEquivalentTo(entry, options => options.Excluding(e => e.ExpiresAt));
        result!.ExpiresAt.Should().BeCloseTo(
            before + new AuthorizationServerOptions().TokenEndpoint.RefreshTokenLifetime, TimeSpan.FromSeconds(5));
    }

    [Fact]
    public async Task FindAsync_returns_null_for_unknown_handle()
    {
        var store = CreateStore();

        var result = await store.FindAsync("never-stored-handle", CancellationToken.None);

        result.Should().BeNull();
    }

    [Fact]
    public async Task FindAsync_returns_null_after_TryConsumeAsync_succeeds()
    {
        var store = CreateStore();
        const string handle = "find-after-consume";

        await store.StoreAsync(handle, BuildEntry(), CancellationToken.None);
        await store.TryConsumeAsync(handle, "client-a", CancellationToken.None);

        var result = await store.FindAsync(handle, CancellationToken.None);

        result.Should().BeNull(because: "a consumed grant must no longer be returned by FindAsync");
    }

    [Fact]
    public async Task FindAsync_multiple_calls_do_not_consume_token_and_TryConsumeAsync_still_succeeds()
    {
        var store = CreateStore();
        const string handle = "find-is-non-consuming";
        var entry = BuildEntry(clientId: "client-a", familyId: "fam-find-nonconsume");

        await store.StoreAsync(handle, entry, CancellationToken.None);

        (await store.FindAsync(handle, CancellationToken.None)).Should().NotBeNull();
        (await store.FindAsync(handle, CancellationToken.None)).Should().NotBeNull();
        (await store.FindAsync(handle, CancellationToken.None)).Should().NotBeNull();

        var outcome = await store.TryConsumeAsync(handle, "client-a", CancellationToken.None);

        outcome.Should().BeOfType<RefreshTokenConsumptionResult.Consumed>(
            because: "FindAsync is read-only and must never consume the token");
    }

    // ── Clamp arithmetic (§5): ExpiresAt = min(now + RefreshTokenLifetime, FamilyAbsoluteExpiry) ──

    [Fact]
    public async Task StoreAsync_clamps_ExpiresAt_to_now_plus_RefreshTokenLifetime_when_that_is_the_smaller_bound()
    {
        var startTime = new DateTimeOffset(2090, 1, 1, 12, 0, 0, TimeSpan.Zero);
        var tp = new FakeTimeProvider(startTime);
        var lifetime = TimeSpan.FromDays(1);
        var familyAbsoluteExpiry = startTime.AddDays(365); // far beyond the per-token lifetime
        var grantStore = new InMemoryRefreshTokenGrantStore();
        var store = CreateStore(
            grantStore: grantStore,
            serverOptions: new AuthorizationServerOptions { TokenEndpoint = { RefreshTokenLifetime = lifetime } },
            timeProvider: tp);
        const string handle = "clamp-lifetime-bound";

        await store.StoreAsync(handle, BuildEntry(familyAbsoluteExpiry: familyAbsoluteExpiry), CancellationToken.None);

        var grant = await grantStore.FindByHandleAsync(new StoreKey(ComputeExpectedHandleHash(handle)), CancellationToken.None);
        grant!.ExpiresAt.Should().Be(startTime + lifetime,
            because: "when now + RefreshTokenLifetime is the smaller of the two bounds, it wins the clamp");
    }

    [Fact]
    public async Task StoreAsync_clamps_ExpiresAt_to_FamilyAbsoluteExpiry_when_that_is_the_smaller_bound()
    {
        var startTime = new DateTimeOffset(2090, 1, 1, 12, 0, 0, TimeSpan.Zero);
        var tp = new FakeTimeProvider(startTime);
        var lifetime = TimeSpan.FromDays(365); // far beyond the family's absolute cap
        var familyAbsoluteExpiry = startTime.AddDays(1);
        var grantStore = new InMemoryRefreshTokenGrantStore();
        var store = CreateStore(
            grantStore: grantStore,
            serverOptions: new AuthorizationServerOptions { TokenEndpoint = { RefreshTokenLifetime = lifetime } },
            timeProvider: tp);
        const string handle = "clamp-family-bound";

        await store.StoreAsync(handle, BuildEntry(familyAbsoluteExpiry: familyAbsoluteExpiry), CancellationToken.None);

        var grant = await grantStore.FindByHandleAsync(new StoreKey(ComputeExpectedHandleHash(handle)), CancellationToken.None);
        grant!.ExpiresAt.Should().Be(familyAbsoluteExpiry,
            because: "when FamilyAbsoluteExpiry is the smaller of the two bounds, the whole family's ceiling wins");
    }

    [Fact]
    public async Task StoreAsync_persists_FamilyAbsoluteExpiry_verbatim_as_a_queryable_column()
    {
        var grantStore = new InMemoryRefreshTokenGrantStore();
        var store = CreateStore(grantStore: grantStore);
        const string handle = "family-absolute-expiry-column";
        var familyAbsoluteExpiry = new DateTimeOffset(2095, 6, 1, 0, 0, 0, TimeSpan.Zero);

        await store.StoreAsync(handle, BuildEntry(familyAbsoluteExpiry: familyAbsoluteExpiry), CancellationToken.None);

        var grant = await grantStore.FindByHandleAsync(new StoreKey(ComputeExpectedHandleHash(handle)), CancellationToken.None);
        grant!.FamilyAbsoluteExpiry.Should().Be(familyAbsoluteExpiry);
    }

    // ── FindAsync / TryConsumeAsync logical expiry (accept-grace) ────────────────────────────────

    // Note: the coordinator computes ExpiresAt itself as min(now + RefreshTokenLifetime,
    // FamilyAbsoluteExpiry) at StoreAsync time (§5) — the ExpiresAt value on the incoming
    // RefreshTokenEntry passed to StoreAsync is NOT used for this computation. These tests
    // therefore control expiry via RefreshTokenLifetime, not via BuildEntry's expiresAt parameter.

    [Fact]
    public async Task TryConsumeAsync_returns_NotFound_when_time_is_past_ExpiresAt_plus_tolerance()
    {
        var startTime = new DateTimeOffset(2090, 1, 1, 12, 0, 0, TimeSpan.Zero);
        var lifetime = TimeSpan.FromMinutes(1);
        var tp = new FakeTimeProvider(startTime);
        var store = CreateStore(
            serverOptions: new AuthorizationServerOptions { TokenEndpoint = { RefreshTokenLifetime = lifetime } },
            timeProvider: tp);
        const string handle = "consume-expiry-check";

        await store.StoreAsync(handle, BuildEntry(issuedAt: startTime), CancellationToken.None);
        tp.Advance(TimeSpan.FromMinutes(2));

        var outcome = await store.TryConsumeAsync(handle, "client-a", CancellationToken.None);

        outcome.Should().BeOfType<RefreshTokenConsumptionResult.NotFound>();
    }

    [Fact]
    public async Task TryConsumeAsync_at_ExpiresAt_exactly_is_still_valid_within_tolerance()
    {
        var startTime = new DateTimeOffset(2090, 1, 1, 12, 0, 0, TimeSpan.Zero);
        var tolerance = TimeSpan.FromSeconds(5);
        var lifetime = TimeSpan.FromMinutes(1);
        var tp = new FakeTimeProvider(startTime);
        var store = CreateStore(
            serverOptions: new AuthorizationServerOptions
            {
                ClockSkewTolerance = tolerance,
                TokenEndpoint = { RefreshTokenLifetime = lifetime },
            },
            timeProvider: tp);
        const string handle = "clock-skew-at-expires";

        await store.StoreAsync(handle, BuildEntry(issuedAt: startTime), CancellationToken.None);
        tp.Advance(lifetime);

        var outcome = await store.TryConsumeAsync(handle, "client-a", CancellationToken.None);

        outcome.Should().BeOfType<RefreshTokenConsumptionResult.Consumed>(
            because: "now == ExpiresAt is still valid: the check is now >= ExpiresAt + tolerance");
    }

    [Fact]
    public async Task TryConsumeAsync_at_ExpiresAt_plus_tolerance_is_expired()
    {
        var startTime = new DateTimeOffset(2090, 1, 1, 12, 0, 0, TimeSpan.Zero);
        var tolerance = TimeSpan.FromSeconds(5);
        var lifetime = TimeSpan.FromMinutes(1);
        var tp = new FakeTimeProvider(startTime);
        var store = CreateStore(
            serverOptions: new AuthorizationServerOptions
            {
                ClockSkewTolerance = tolerance,
                TokenEndpoint = { RefreshTokenLifetime = lifetime },
            },
            timeProvider: tp);
        const string handle = "clock-skew-boundary";

        await store.StoreAsync(handle, BuildEntry(issuedAt: startTime), CancellationToken.None);
        tp.Advance(lifetime + tolerance);

        var outcome = await store.TryConsumeAsync(handle, "client-a", CancellationToken.None);

        outcome.Should().BeOfType<RefreshTokenConsumptionResult.NotFound>();
    }

    [Fact]
    public async Task FindAsync_returns_null_when_time_is_past_ExpiresAt_plus_tolerance()
    {
        var startTime = new DateTimeOffset(2090, 1, 1, 12, 0, 0, TimeSpan.Zero);
        var lifetime = TimeSpan.FromMinutes(1);
        var tp = new FakeTimeProvider(startTime);
        var store = CreateStore(
            serverOptions: new AuthorizationServerOptions { TokenEndpoint = { RefreshTokenLifetime = lifetime } },
            timeProvider: tp);
        const string handle = "find-expiry-check";

        await store.StoreAsync(handle, BuildEntry(issuedAt: startTime), CancellationToken.None);
        tp.Advance(TimeSpan.FromMinutes(2));

        var result = await store.FindAsync(handle, CancellationToken.None);

        result.Should().BeNull();
    }

    // ── §4 decision-tree ordering: NotFound → Revoked → AlreadyConsumed → expiry → ClientMismatch ─

    [Fact]
    public async Task TryConsumeAsync_returns_NotFound_for_unknown_handle()
    {
        var store = CreateStore();

        var outcome = await store.TryConsumeAsync("never-stored", "client-a", CancellationToken.None);

        outcome.Should().BeOfType<RefreshTokenConsumptionResult.NotFound>();
    }

    [Fact]
    public async Task TryConsumeAsync_returns_Revoked_for_token_in_revoked_family()
    {
        var store = CreateStore();
        const string handle = "revoked-family-consume";
        const string familyId = "fam-revoked";

        await store.StoreAsync(handle, BuildEntry(familyId: familyId), CancellationToken.None);
        await store.RevokeFamilyAsync(familyId, CancellationToken.None);

        var outcome = await store.TryConsumeAsync(handle, "client-a", CancellationToken.None);

        outcome.Should().BeOfType<RefreshTokenConsumptionResult.Revoked>()
            .Which.FamilyId.Should().Be(familyId);
    }

    [Fact]
    public async Task TryConsumeAsync_returns_AlreadyConsumed_for_replay_after_successful_consumption()
    {
        var store = CreateStore();
        const string handle = "replay-attack-handle";
        const string familyId = "fam-replay";

        await store.StoreAsync(handle, BuildEntry(familyId: familyId), CancellationToken.None);
        var first = await store.TryConsumeAsync(handle, "client-a", CancellationToken.None);
        first.Should().BeOfType<RefreshTokenConsumptionResult.Consumed>();

        var replay = await store.TryConsumeAsync(handle, "client-a", CancellationToken.None);

        replay.Should().BeOfType<RefreshTokenConsumptionResult.AlreadyConsumed>()
            .Which.FamilyId.Should().Be(familyId);
    }

    [Fact]
    public async Task TryConsumeAsync_returns_ClientMismatch_when_client_does_not_match()
    {
        var store = CreateStore();
        const string handle = "client-mismatch-handle";

        await store.StoreAsync(handle, BuildEntry(clientId: "client-a"), CancellationToken.None);

        var outcome = await store.TryConsumeAsync(handle, "client-b", CancellationToken.None);

        outcome.Should().BeOfType<RefreshTokenConsumptionResult.ClientMismatch>();
    }

    [Fact]
    public async Task TryConsumeAsync_ClientMismatch_does_not_consume_token_allowing_legitimate_client_to_succeed()
    {
        var store = CreateStore();
        const string handle = "client-mismatch-no-consume";

        await store.StoreAsync(handle, BuildEntry(clientId: "client-a"), CancellationToken.None);

        var mismatch = await store.TryConsumeAsync(handle, "client-b", CancellationToken.None);
        mismatch.Should().BeOfType<RefreshTokenConsumptionResult.ClientMismatch>();

        var legitimate = await store.TryConsumeAsync(handle, "client-a", CancellationToken.None);
        legitimate.Should().BeOfType<RefreshTokenConsumptionResult.Consumed>(
            because: "ClientMismatch must leave the token intact for the legitimate client");
    }

    [Fact]
    public async Task TryConsumeAsync_returns_Revoked_not_ClientMismatch_when_family_is_revoked_and_client_mismatches()
    {
        var store = CreateStore();
        const string handle = "revoked-and-wrong-client";
        const string familyId = "fam-revoked-mismatch";

        await store.StoreAsync(handle, BuildEntry(clientId: "client-a", familyId: familyId), CancellationToken.None);
        await store.RevokeFamilyAsync(familyId, CancellationToken.None);

        var outcome = await store.TryConsumeAsync(handle, "client-b", CancellationToken.None);

        outcome.Should().BeOfType<RefreshTokenConsumptionResult.Revoked>(
            because: "§4: the revocation check happens before the client-mismatch check");
    }

    // ── #386 gate: IsFamilyRevokedAsync catches a family revoked out-of-band of this row's own status ─

    [Fact]
    public async Task TryConsumeAsync_returns_Revoked_when_grant_reads_Active_but_IsFamilyRevokedAsync_reports_true()
    {
        // Simulates the exact issue #386 exploit: this grant's OWN row is still Active (e.g. it was
        // inserted strictly after a sibling's RevokeFamilyAsync returned), but the family reads
        // revoked. The gate must catch this regardless of the row's own status.
        const string familyId = "fam-386-consume";
        var innerStore = new InMemoryRefreshTokenGrantStore();
        var store = CreateStore(grantStore: new FamilyRevokedOverrideGrantStore(innerStore, familyId));
        const string handle = "family-revoked-out-of-band-consume";

        await store.StoreAsync(handle, BuildEntry(familyId: familyId), CancellationToken.None);

        var outcome = await store.TryConsumeAsync(handle, "client-a", CancellationToken.None);

        outcome.Should().BeOfType<RefreshTokenConsumptionResult.Revoked>()
            .Which.FamilyId.Should().Be(familyId);
    }

    [Fact]
    public async Task FindAsync_returns_null_when_grant_reads_Active_but_IsFamilyRevokedAsync_reports_true()
    {
        const string familyId = "fam-386-find";
        var innerStore = new InMemoryRefreshTokenGrantStore();
        var store = CreateStore(grantStore: new FamilyRevokedOverrideGrantStore(innerStore, familyId));
        const string handle = "family-revoked-out-of-band-find";

        await store.StoreAsync(handle, BuildEntry(familyId: familyId), CancellationToken.None);

        var result = await store.FindAsync(handle, CancellationToken.None);

        result.Should().BeNull(
            because: "introspection must not report a revoked-family grant as live, even though its own row is Active");
    }

    [Fact]
    public async Task TryConsumeAsync_returns_Revoked_not_ClientMismatch_when_IsFamilyRevokedAsync_reports_true_and_client_mismatches()
    {
        const string familyId = "fam-386-mismatch";
        var innerStore = new InMemoryRefreshTokenGrantStore();
        var store = CreateStore(grantStore: new FamilyRevokedOverrideGrantStore(innerStore, familyId));
        const string handle = "family-revoked-out-of-band-mismatch";

        await store.StoreAsync(handle, BuildEntry(clientId: "client-a", familyId: familyId), CancellationToken.None);

        var outcome = await store.TryConsumeAsync(handle, "client-b", CancellationToken.None);

        outcome.Should().BeOfType<RefreshTokenConsumptionResult.Revoked>(
            because: "§11: the family-revoked gate runs before the client-mismatch check, same ordering as the row's own Revoked status");
    }

    [Fact]
    public async Task TryConsumeAsync_returns_Revoked_not_AlreadyConsumed_when_consumed_then_family_revoked_then_replayed()
    {
        // §4: the coordinator checks Status == Revoked before Status == Consumed. Combined with
        // the grant store overwriting a Consumed row's Status to Revoked on RevokeFamilyAsync
        // (both are terminal, non-Active states — see InMemoryRefreshTokenGrantStore's remarks),
        // a replay against a token that was consumed and then had its family revoked reads as
        // Revoked, not AlreadyConsumed.
        var store = CreateStore();
        const string handle = "replay-after-revoke-after-consume";
        const string familyId = "fam-precedence-test";

        await store.StoreAsync(handle, BuildEntry(clientId: "client-a", familyId: familyId), CancellationToken.None);
        var consumeOutcome = await store.TryConsumeAsync(handle, "client-a", CancellationToken.None);
        consumeOutcome.Should().BeOfType<RefreshTokenConsumptionResult.Consumed>();

        await store.RevokeFamilyAsync(familyId, CancellationToken.None);
        var replayOutcome = await store.TryConsumeAsync(handle, "client-a", CancellationToken.None);

        replayOutcome.Should().BeOfType<RefreshTokenConsumptionResult.Revoked>(
                because: "the revocation check happens before the Consumed check, and revocation " +
                          "overwrites a Consumed row's status to Revoked")
            .Which.FamilyId.Should().Be(familyId);
    }

    // ── §4/§7 MUST-pin: cleartext decisions never touch Unprotect ────────────────────────────────

    [Fact]
    public async Task TryConsumeAsync_returns_AlreadyConsumed_without_throwing_even_when_ProtectedPayload_is_corrupt()
    {
        // A grant with a deliberately corrupt/unparseable ProtectedPayload must still resolve
        // AlreadyConsumed purely from the cleartext Status column — the ADR 0014 §4/§7 sign-off
        // item 3 concern: reuse detection must never ride on a successful decrypt.
        var grantStore = new InMemoryRefreshTokenGrantStore();
        var store = CreateStore(grantStore: grantStore);
        const string handle = "corrupt-payload-consumed";
        const string familyId = "fam-corrupt-consumed";
        var key = new StoreKey(ComputeExpectedHandleHash(handle));

        await grantStore.InsertAsync(new RefreshTokenGrant
        {
            HandleHash = key,
            FamilyId = familyId,
            Subject = "user-1",
            ClientId = "client-a",
            FamilyAbsoluteExpiry = FarFuture,
            ExpiresAt = FarFuture,
            Status = RefreshGrantStatus.Consumed,
            ProtectedPayload = new byte[] { 0xDE, 0xAD, 0xBE, 0xEF },
        }, CancellationToken.None);

        var outcome = await store.TryConsumeAsync(handle, "client-a", CancellationToken.None);

        outcome.Should().BeOfType<RefreshTokenConsumptionResult.AlreadyConsumed>()
            .Which.FamilyId.Should().Be(familyId);
    }

    [Fact]
    public async Task TryConsumeAsync_returns_Revoked_without_throwing_even_when_ProtectedPayload_is_corrupt()
    {
        var grantStore = new InMemoryRefreshTokenGrantStore();
        var store = CreateStore(grantStore: grantStore);
        const string handle = "corrupt-payload-revoked";
        const string familyId = "fam-corrupt-revoked";
        var key = new StoreKey(ComputeExpectedHandleHash(handle));

        await grantStore.InsertAsync(new RefreshTokenGrant
        {
            HandleHash = key,
            FamilyId = familyId,
            Subject = "user-1",
            ClientId = "client-a",
            FamilyAbsoluteExpiry = FarFuture,
            ExpiresAt = FarFuture,
            Status = RefreshGrantStatus.Revoked,
            ProtectedPayload = new byte[] { 0xDE, 0xAD, 0xBE, 0xEF },
        }, CancellationToken.None);

        var outcome = await store.TryConsumeAsync(handle, "client-a", CancellationToken.None);

        outcome.Should().BeOfType<RefreshTokenConsumptionResult.Revoked>()
            .Which.FamilyId.Should().Be(familyId);
    }

    [Fact]
    public async Task TryConsumeAsync_returns_NotFound_without_throwing_when_expired_grant_has_corrupt_ProtectedPayload()
    {
        var grantStore = new InMemoryRefreshTokenGrantStore();
        var startTime = new DateTimeOffset(2090, 1, 1, 12, 0, 0, TimeSpan.Zero);
        var tp = new FakeTimeProvider(startTime);
        var store = CreateStore(grantStore: grantStore, timeProvider: tp);
        const string handle = "corrupt-payload-expired";
        var key = new StoreKey(ComputeExpectedHandleHash(handle));

        await grantStore.InsertAsync(new RefreshTokenGrant
        {
            HandleHash = key,
            FamilyId = "fam-corrupt-expired",
            Subject = "user-1",
            ClientId = "client-a",
            FamilyAbsoluteExpiry = FarFuture,
            ExpiresAt = startTime.AddMinutes(1),
            Status = RefreshGrantStatus.Active,
            ProtectedPayload = new byte[] { 0xDE, 0xAD, 0xBE, 0xEF },
        }, CancellationToken.None);
        tp.Advance(TimeSpan.FromMinutes(2));

        var outcome = await store.TryConsumeAsync(handle, "client-a", CancellationToken.None);

        outcome.Should().BeOfType<RefreshTokenConsumptionResult.NotFound>(
            because: "expiry is decided from the cleartext ExpiresAt column before any Unprotect");
    }

    [Fact]
    public async Task TryConsumeAsync_returns_ClientMismatch_without_throwing_when_active_grant_has_corrupt_ProtectedPayload()
    {
        var grantStore = new InMemoryRefreshTokenGrantStore();
        var store = CreateStore(grantStore: grantStore);
        const string handle = "corrupt-payload-mismatch";
        var key = new StoreKey(ComputeExpectedHandleHash(handle));

        await grantStore.InsertAsync(new RefreshTokenGrant
        {
            HandleHash = key,
            FamilyId = "fam-corrupt-mismatch",
            Subject = "user-1",
            ClientId = "client-a",
            FamilyAbsoluteExpiry = FarFuture,
            ExpiresAt = FarFuture,
            Status = RefreshGrantStatus.Active,
            ProtectedPayload = new byte[] { 0xDE, 0xAD, 0xBE, 0xEF },
        }, CancellationToken.None);

        var outcome = await store.TryConsumeAsync(handle, "client-b", CancellationToken.None);

        outcome.Should().BeOfType<RefreshTokenConsumptionResult.ClientMismatch>(
            because: "ClientMismatch is decided from the cleartext ClientId column before any Unprotect");
    }

    // ── §7 single Unprotect catch site: only the happy path decrypts, and only it can fail ──────

    [Fact]
    public async Task TryConsumeAsync_returns_NotFound_when_the_winning_consume_cannot_be_unprotected()
    {
        // Two stores share the same grant store but use independent DP key rings. Store 1 writes
        // the grant; store 2 wins the CAS pivot but cannot decrypt the payload — the sole
        // Unprotect call's only failure mode, degrading to NotFound (fail-closed: already dead).
        var grantStore = new InMemoryRefreshTokenGrantStore();
        var dp1 = new EphemeralDataProtectionProvider();
        var dp2 = new EphemeralDataProtectionProvider();
        var store1 = CreateStore(grantStore: grantStore, dp: dp1);
        var store2 = CreateStore(grantStore: grantStore, dp: dp2);
        const string handle = "dp-rotation-consume";

        await store1.StoreAsync(handle, BuildEntry(), CancellationToken.None);

        var outcome = await store2.TryConsumeAsync(handle, "client-a", CancellationToken.None);

        outcome.Should().BeOfType<RefreshTokenConsumptionResult.NotFound>();
    }

    [Fact]
    public async Task TryConsumeAsync_after_NotFound_from_unreadable_payload_does_not_allow_a_second_successful_consume()
    {
        // The row is already marked Consumed by the losing decrypt attempt — the token is dead
        // even though NotFound was returned, so a subsequent attempt (e.g. with a working key
        // ring) must not be able to consume it again.
        var grantStore = new InMemoryRefreshTokenGrantStore();
        var dp1 = new EphemeralDataProtectionProvider();
        var dp2 = new EphemeralDataProtectionProvider();
        var store1 = CreateStore(grantStore: grantStore, dp: dp1);
        var store2 = CreateStore(grantStore: grantStore, dp: dp2);
        const string handle = "dp-rotation-consume-then-replay";

        await store1.StoreAsync(handle, BuildEntry(), CancellationToken.None);
        await store2.TryConsumeAsync(handle, "client-a", CancellationToken.None);

        var replay = await store1.TryConsumeAsync(handle, "client-a", CancellationToken.None);

        replay.Should().BeOfType<RefreshTokenConsumptionResult.AlreadyConsumed>(
            because: "the CAS already committed Consumed on the failed-decrypt attempt");
    }

    [Fact]
    public async Task FindAsync_returns_null_when_entry_cannot_be_unprotected()
    {
        var grantStore = new InMemoryRefreshTokenGrantStore();
        var dp1 = new EphemeralDataProtectionProvider();
        var dp2 = new EphemeralDataProtectionProvider();
        var store1 = CreateStore(grantStore: grantStore, dp: dp1);
        var store2 = CreateStore(grantStore: grantStore, dp: dp2);
        const string handle = "dp-rotation-find";

        await store1.StoreAsync(handle, BuildEntry(), CancellationToken.None);

        var result = await store2.FindAsync(handle, CancellationToken.None);

        result.Should().BeNull();
    }

    // ── CAS pivot: lost-race re-read ──────────────────────────────────────────────────────────────

    [Fact]
    public async Task TryConsumeAsync_lost_race_resolves_to_AlreadyConsumed_via_re_read()
    {
        var inner = new InMemoryRefreshTokenGrantStore();
        var dp = new EphemeralDataProtectionProvider();
        var seedStore = CreateStore(grantStore: inner, dp: dp);
        const string handle = "race-losing-handle";
        const string familyId = "fam-raced";
        await seedStore.StoreAsync(handle, BuildEntry(familyId: familyId), CancellationToken.None);

        var racingStore = CreateStore(grantStore: new RaceLosingGrantStore(inner), dp: dp);

        var outcome = await racingStore.TryConsumeAsync(handle, "client-a", CancellationToken.None);

        outcome.Should().BeOfType<RefreshTokenConsumptionResult.AlreadyConsumed>()
            .Which.FamilyId.Should().Be(familyId);
    }

    [Fact]
    public async Task TryConsumeAsync_lost_race_resolves_to_Revoked_when_the_winner_revoked_the_family_first()
    {
        var inner = new InMemoryRefreshTokenGrantStore();
        var dp = new EphemeralDataProtectionProvider();
        var seedStore = CreateStore(grantStore: inner, dp: dp);
        const string handle = "race-losing-then-revoked-handle";
        const string familyId = "fam-raced-revoked";
        await seedStore.StoreAsync(handle, BuildEntry(familyId: familyId), CancellationToken.None);

        var racingStore = CreateStore(grantStore: new RaceLosingThenRevokingGrantStore(inner, familyId), dp: dp);

        var outcome = await racingStore.TryConsumeAsync(handle, "client-a", CancellationToken.None);

        outcome.Should().BeOfType<RefreshTokenConsumptionResult.Revoked>()
            .Which.FamilyId.Should().Be(familyId);
    }

    [Fact]
    public async Task TryConsumeAsync_exactly_one_Consumed_under_high_concurrency()
    {
        var store = CreateStore();
        const string handle = "concurrent-handle";

        await store.StoreAsync(handle, BuildEntry(), CancellationToken.None);

        const int concurrentTasks = 100;
        using var gate = new SemaphoreSlim(0, concurrentTasks);

        var tasks = Enumerable.Range(0, concurrentTasks)
            .Select(_ => Task.Run(async () =>
            {
                await gate.WaitAsync();
                return await store.TryConsumeAsync(handle, "client-a", CancellationToken.None);
            }))
            .ToArray();

        gate.Release(concurrentTasks);
        var outcomes = await Task.WhenAll(tasks);

        outcomes.Count(o => o is RefreshTokenConsumptionResult.Consumed).Should().Be(1);
        outcomes.Count(o => o is RefreshTokenConsumptionResult.AlreadyConsumed).Should().Be(concurrentTasks - 1);
        outcomes.Count(o => o is RefreshTokenConsumptionResult.NotFound).Should().Be(0);
    }

    // ── §8 fail-closed: DataProtection Protect() faults wrap as ZeeKayDaStoreException ─────────

    [Fact]
    public async Task StoreAsync_wraps_DataProtection_Protect_failure_in_ZeeKayDaStoreException()
    {
        var faultingDp = new ProtectFailingDataProtectionProvider(new EphemeralDataProtectionProvider());
        var store = CreateStore(dp: faultingDp);

        var act = async () => await store.StoreAsync("protect-failure-handle", BuildEntry(), CancellationToken.None);

        var assertion = await act.Should().ThrowAsync<ZeeKayDaStoreException>();
        assertion.Which.InnerException.Should().BeOfType<InvalidOperationException>();
    }

    // ── §8 fail-closed: grant-store faults wrap as ZeeKayDaStoreException ───────────────────────

    [Fact]
    public async Task StoreAsync_wraps_grantStore_exception_in_ZeeKayDaStoreException()
    {
        var store = CreateStore(grantStore: new ThrowingGrantStore());

        var act = async () => await store.StoreAsync("handle", BuildEntry(), CancellationToken.None);

        var assertion = await act.Should().ThrowAsync<ZeeKayDaStoreException>();
        assertion.Which.InnerException.Should().BeOfType<InvalidOperationException>();
    }

    [Fact]
    public async Task TryConsumeAsync_wraps_grantStore_FindByHandleAsync_exception_in_ZeeKayDaStoreException()
    {
        var store = CreateStore(grantStore: new ThrowingGrantStore());

        var act = async () => await store.TryConsumeAsync("handle", "client-a", CancellationToken.None);

        await act.Should().ThrowAsync<ZeeKayDaStoreException>();
    }

    [Fact]
    public async Task RevokeFamilyAsync_wraps_grantStore_exception_in_ZeeKayDaStoreException()
    {
        var store = CreateStore(grantStore: new ThrowingGrantStore());

        var act = async () => await store.RevokeFamilyAsync("family-1", CancellationToken.None);

        await act.Should().ThrowAsync<ZeeKayDaStoreException>();
    }

    [Fact]
    public async Task TryConsumeAsync_rethrows_OperationCanceledException_from_TryMarkConsumedAsync_unwrapped()
    {
        var grantStore = new CancellationThrowingOnMarkConsumedGrantStore(new InMemoryRefreshTokenGrantStore());
        var store = CreateStore(grantStore: grantStore);
        await store.StoreAsync("handle", BuildEntry(), CancellationToken.None);

        var act = async () => await store.TryConsumeAsync("handle", "client-a", CancellationToken.None);

        await act.Should().ThrowAsync<OperationCanceledException>();
    }

    // ── Sealing member (ADR 0014 §4, mirroring ADR 0013 §1) ──────────────────────────────────────

    [Fact]
    public void SealAsFrameworkOwnedProtocol_can_be_invoked_through_the_interface_without_throwing()
    {
        IRefreshTokenStore store = CreateStore();

        var act = () => store.SealAsFrameworkOwnedProtocol();

        act.Should().NotThrow();
    }

    // ── Cancellation is not a store fault ─────────────────────────────────────────────────────────

    [Fact]
    public async Task StoreAsync_rethrows_OperationCanceledException_unwrapped()
    {
        var store = CreateStore();
        using var cts = new CancellationTokenSource();
        cts.Cancel();

        var act = async () => await store.StoreAsync("handle", BuildEntry(), cts.Token);

        await act.Should().ThrowAsync<OperationCanceledException>();
    }

    // ── Argument guards ───────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task StoreAsync_throws_ArgumentNullException_for_null_tokenHandle()
    {
        var store = CreateStore();

        var act = async () => await store.StoreAsync(null!, BuildEntry(), CancellationToken.None);

        await act.Should().ThrowAsync<ArgumentNullException>();
    }

    [Fact]
    public async Task StoreAsync_throws_ArgumentNullException_for_null_entry()
    {
        var store = CreateStore();

        var act = async () => await store.StoreAsync("handle", null!, CancellationToken.None);

        await act.Should().ThrowAsync<ArgumentNullException>();
    }

    [Fact]
    public async Task TryConsumeAsync_throws_ArgumentNullException_for_null_clientId()
    {
        var store = CreateStore();

        var act = async () => await store.TryConsumeAsync("handle", null!, CancellationToken.None);

        await act.Should().ThrowAsync<ArgumentNullException>();
    }

    [Fact]
    public async Task RevokeFamilyAsync_throws_ArgumentNullException_for_null_familyId()
    {
        var store = CreateStore();

        var act = async () => await store.RevokeFamilyAsync(null!, CancellationToken.None);

        await act.Should().ThrowAsync<ArgumentNullException>();
    }

    // ── Helpers ───────────────────────────────────────────────────────────────────────────────────

    private static string ComputeExpectedHandleHash(string handle)
    {
        var bytes = System.Security.Cryptography.SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(handle));
        return System.Buffers.Text.Base64Url.EncodeToString(bytes);
    }

    private sealed class ThrowingGrantStore : IRefreshTokenGrantStore
    {
        public ValueTask InsertAsync(RefreshTokenGrant grant, CancellationToken cancellationToken)
            => throw new InvalidOperationException("Simulated grant store failure.");

        public ValueTask<RefreshTokenGrant?> FindByHandleAsync(StoreKey handleHash, CancellationToken cancellationToken)
            => throw new InvalidOperationException("Simulated grant store failure.");

        public ValueTask<bool> TryMarkConsumedAsync(StoreKey handleHash, CancellationToken cancellationToken)
            => throw new InvalidOperationException("Simulated grant store failure.");

        public ValueTask RevokeFamilyAsync(string familyId, CancellationToken cancellationToken)
            => throw new InvalidOperationException("Simulated grant store failure.");

        public ValueTask RevokeBySubjectAsync(string subject, CancellationToken cancellationToken)
            => throw new InvalidOperationException("Simulated grant store failure.");

        public ValueTask<bool> IsFamilyRevokedAsync(string familyId, CancellationToken cancellationToken)
            => throw new InvalidOperationException("Simulated grant store failure.");
    }

    /// <summary>
    /// Wraps a real grant store; on <see cref="TryMarkConsumedAsync"/> it first performs the CAS
    /// through the real store (as if another concurrent consumer had just won) and then reports
    /// the transition as lost, deterministically exercising the §4 "lost the race" re-read path.
    /// </summary>
    private sealed class RaceLosingGrantStore : IRefreshTokenGrantStore
    {
        private readonly IRefreshTokenGrantStore _inner;

        public RaceLosingGrantStore(IRefreshTokenGrantStore inner) => _inner = inner;

        public ValueTask InsertAsync(RefreshTokenGrant grant, CancellationToken cancellationToken)
            => _inner.InsertAsync(grant, cancellationToken);

        public ValueTask<RefreshTokenGrant?> FindByHandleAsync(StoreKey handleHash, CancellationToken cancellationToken)
            => _inner.FindByHandleAsync(handleHash, cancellationToken);

        public async ValueTask<bool> TryMarkConsumedAsync(StoreKey handleHash, CancellationToken cancellationToken)
        {
            await _inner.TryMarkConsumedAsync(handleHash, cancellationToken).ConfigureAwait(false);
            return false;
        }

        public ValueTask RevokeFamilyAsync(string familyId, CancellationToken cancellationToken)
            => _inner.RevokeFamilyAsync(familyId, cancellationToken);

        public ValueTask RevokeBySubjectAsync(string subject, CancellationToken cancellationToken)
            => _inner.RevokeBySubjectAsync(subject, cancellationToken);

        public ValueTask<bool> IsFamilyRevokedAsync(string familyId, CancellationToken cancellationToken)
            => _inner.IsFamilyRevokedAsync(familyId, cancellationToken);
    }

    /// <summary>
    /// Like <see cref="RaceLosingGrantStore"/>, but the simulated winner also revokes the family
    /// immediately after winning the CAS, so the losing re-read observes <c>Revoked</c> rather
    /// than <c>Consumed</c>.
    /// </summary>
    private sealed class RaceLosingThenRevokingGrantStore : IRefreshTokenGrantStore
    {
        private readonly IRefreshTokenGrantStore _inner;
        private readonly string _familyId;

        public RaceLosingThenRevokingGrantStore(IRefreshTokenGrantStore inner, string familyId)
        {
            _inner = inner;
            _familyId = familyId;
        }

        public ValueTask InsertAsync(RefreshTokenGrant grant, CancellationToken cancellationToken)
            => _inner.InsertAsync(grant, cancellationToken);

        public ValueTask<RefreshTokenGrant?> FindByHandleAsync(StoreKey handleHash, CancellationToken cancellationToken)
            => _inner.FindByHandleAsync(handleHash, cancellationToken);

        public async ValueTask<bool> TryMarkConsumedAsync(StoreKey handleHash, CancellationToken cancellationToken)
        {
            await _inner.TryMarkConsumedAsync(handleHash, cancellationToken).ConfigureAwait(false);
            await _inner.RevokeFamilyAsync(_familyId, cancellationToken).ConfigureAwait(false);
            return false;
        }

        public ValueTask RevokeFamilyAsync(string familyId, CancellationToken cancellationToken)
            => _inner.RevokeFamilyAsync(familyId, cancellationToken);

        public ValueTask RevokeBySubjectAsync(string subject, CancellationToken cancellationToken)
            => _inner.RevokeBySubjectAsync(subject, cancellationToken);

        public ValueTask<bool> IsFamilyRevokedAsync(string familyId, CancellationToken cancellationToken)
            => _inner.IsFamilyRevokedAsync(familyId, cancellationToken);
    }

    private sealed class CancellationThrowingOnMarkConsumedGrantStore : IRefreshTokenGrantStore
    {
        private readonly IRefreshTokenGrantStore _inner;

        public CancellationThrowingOnMarkConsumedGrantStore(IRefreshTokenGrantStore inner) => _inner = inner;

        public ValueTask InsertAsync(RefreshTokenGrant grant, CancellationToken cancellationToken)
            => _inner.InsertAsync(grant, cancellationToken);

        public ValueTask<RefreshTokenGrant?> FindByHandleAsync(StoreKey handleHash, CancellationToken cancellationToken)
            => _inner.FindByHandleAsync(handleHash, cancellationToken);

        public ValueTask<bool> TryMarkConsumedAsync(StoreKey handleHash, CancellationToken cancellationToken)
            => throw new OperationCanceledException();

        public ValueTask RevokeFamilyAsync(string familyId, CancellationToken cancellationToken)
            => _inner.RevokeFamilyAsync(familyId, cancellationToken);

        public ValueTask RevokeBySubjectAsync(string subject, CancellationToken cancellationToken)
            => _inner.RevokeBySubjectAsync(subject, cancellationToken);

        public ValueTask<bool> IsFamilyRevokedAsync(string familyId, CancellationToken cancellationToken)
            => _inner.IsFamilyRevokedAsync(familyId, cancellationToken);
    }

    /// <summary>
    /// Wraps a real grant store; <see cref="IsFamilyRevokedAsync"/> always reports
    /// <see langword="true"/> for <paramref name="revokedFamilyId"/>, regardless of what
    /// <see cref="_inner"/>'s rows actually say — deterministically simulating the issue #386
    /// scenario where a grant's own row still reads <see cref="RefreshGrantStatus.Active"/> but a
    /// sibling's revoke has already committed.
    /// </summary>
    private sealed class FamilyRevokedOverrideGrantStore : IRefreshTokenGrantStore
    {
        private readonly IRefreshTokenGrantStore _inner;
        private readonly string _revokedFamilyId;

        public FamilyRevokedOverrideGrantStore(IRefreshTokenGrantStore inner, string revokedFamilyId)
        {
            _inner = inner;
            _revokedFamilyId = revokedFamilyId;
        }

        public ValueTask InsertAsync(RefreshTokenGrant grant, CancellationToken cancellationToken)
            => _inner.InsertAsync(grant, cancellationToken);

        public ValueTask<RefreshTokenGrant?> FindByHandleAsync(StoreKey handleHash, CancellationToken cancellationToken)
            => _inner.FindByHandleAsync(handleHash, cancellationToken);

        public ValueTask<bool> TryMarkConsumedAsync(StoreKey handleHash, CancellationToken cancellationToken)
            => _inner.TryMarkConsumedAsync(handleHash, cancellationToken);

        public ValueTask RevokeFamilyAsync(string familyId, CancellationToken cancellationToken)
            => _inner.RevokeFamilyAsync(familyId, cancellationToken);

        public ValueTask RevokeBySubjectAsync(string subject, CancellationToken cancellationToken)
            => _inner.RevokeBySubjectAsync(subject, cancellationToken);

        public ValueTask<bool> IsFamilyRevokedAsync(string familyId, CancellationToken cancellationToken)
            => ValueTask.FromResult(string.Equals(familyId, _revokedFamilyId, StringComparison.Ordinal));
    }

    private sealed class ProtectFailingDataProtectionProvider : IDataProtectionProvider
    {
        private readonly IDataProtectionProvider _inner;
        public ProtectFailingDataProtectionProvider(IDataProtectionProvider inner) => _inner = inner;
        public IDataProtector CreateProtector(string purpose) => new ProtectFailingDataProtector(_inner.CreateProtector(purpose));
    }

    private sealed class ProtectFailingDataProtector : IDataProtector
    {
        private readonly IDataProtector _inner;
        public ProtectFailingDataProtector(IDataProtector inner) => _inner = inner;
        public IDataProtector CreateProtector(string purpose) => new ProtectFailingDataProtector(_inner.CreateProtector(purpose));
        public byte[] Protect(byte[] plaintext) => throw new InvalidOperationException("Simulated DP Protect() failure.");
        public byte[] Unprotect(byte[] protectedData) => _inner.Unprotect(protectedData);
    }
}
