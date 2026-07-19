using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Time.Testing;
using ZeeKayDa.Auth.Authorization;
using ZeeKayDa.Auth.Stores;

namespace ZeeKayDa.Auth.Tests.Stores;

/// <summary>
/// Tests for the <c>AuthorizationCodeStore</c> framework coordinator (ADR 0013 §1, §9). Covers
/// the full check-and-consume state machine, the two-catch-site decrypt asymmetry (§7), the
/// fail-closed <c>Guarded(...)</c> wrapper (§8), and cancellation semantics.
/// </summary>
public sealed class AuthorizationCodeStoreTests
{
    private static readonly DateTimeOffset FarFuture = new(2099, 1, 1, 0, 0, 0, TimeSpan.Zero);

    private static AuthorizationCodeStore CreateStore(
        IAuthorizationCodeBackingStore? backingStore = null,
        IDataProtectionProvider? dp = null,
        AuthorizationServerOptions? serverOptions = null,
        TimeProvider? timeProvider = null)
        => new(
            backingStore ?? new InMemoryAuthorizationCodeBackingStore(),
            dp ?? new EphemeralDataProtectionProvider(),
            new OptionsWrapper<AuthorizationServerOptions>(serverOptions ?? new AuthorizationServerOptions()),
            timeProvider ?? TimeProvider.System);

    private static AuthorizationCodeEntry BuildEntry(
        string clientId = "client-a",
        DateTimeOffset? issuedAt = null,
        DateTimeOffset? expiresAt = null) =>
        new()
        {
            ClientId = clientId,
            RedirectUri = "https://app/callback",
            CodeChallenge = "challenge-abc",
            CodeChallengeMethod = CodeChallengeMethod.S256,
            Sub = "user-1",
            Scope = ["openid", "profile"],
            SsoSessionId = "session-1",
            InteractionId = "interaction-1",
            AuthTime = issuedAt ?? DateTimeOffset.UtcNow,
            IssuedAt = issuedAt ?? DateTimeOffset.UtcNow,
            ExpiresAt = expiresAt ?? FarFuture,
        };

    // ── Constructor guards ────────────────────────────────────────────────────────────────────────

    [Fact]
    public void Constructor_throws_ArgumentNullException_for_null_backingStore()
    {
        var act = () => new AuthorizationCodeStore(
            null!,
            new EphemeralDataProtectionProvider(),
            new OptionsWrapper<AuthorizationServerOptions>(new AuthorizationServerOptions()),
            TimeProvider.System);

        act.Should().Throw<ArgumentNullException>();
    }

    [Fact]
    public void Constructor_throws_ArgumentNullException_for_null_dataProtectionProvider()
    {
        var act = () => new AuthorizationCodeStore(
            new InMemoryAuthorizationCodeBackingStore(),
            null!,
            new OptionsWrapper<AuthorizationServerOptions>(new AuthorizationServerOptions()),
            TimeProvider.System);

        act.Should().Throw<ArgumentNullException>();
    }

    [Fact]
    public void Constructor_throws_ArgumentNullException_for_null_serverOptions()
    {
        var act = () => new AuthorizationCodeStore(
            new InMemoryAuthorizationCodeBackingStore(),
            new EphemeralDataProtectionProvider(),
            null!,
            TimeProvider.System);

        act.Should().Throw<ArgumentNullException>();
    }

    [Fact]
    public void Constructor_throws_ArgumentNullException_for_null_timeProvider()
    {
        var act = () => new AuthorizationCodeStore(
            new InMemoryAuthorizationCodeBackingStore(),
            new EphemeralDataProtectionProvider(),
            new OptionsWrapper<AuthorizationServerOptions>(new AuthorizationServerOptions()),
            null!);

        act.Should().Throw<ArgumentNullException>();
    }

    // ── Happy path ────────────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task StoreAsync_then_TryRedeemAsync_with_correct_client_returns_Redeemed()
    {
        var store = CreateStore();
        const string code = "valid-code";

        await store.StoreAsync(code, BuildEntry(clientId: "client-a"), CancellationToken.None);
        var outcome = await store.TryRedeemAsync(code, "client-a", "family-1", CancellationToken.None);

        outcome.Should().BeOfType<AuthorizationCodeRedemptionResult.Redeemed>();
    }

    [Fact]
    public async Task TryRedeemAsync_Redeemed_entry_matches_stored_entry()
    {
        var store = CreateStore();
        const string code = "round-trip-code";
        var entry = BuildEntry();

        await store.StoreAsync(code, entry, CancellationToken.None);
        var outcome = await store.TryRedeemAsync(code, "client-a", "family-1", CancellationToken.None);

        outcome.Should().BeOfType<AuthorizationCodeRedemptionResult.Redeemed>()
            .Which.Entry.Should().BeEquivalentTo(entry);
    }

    // ── Client mismatch — does not consume ───────────────────────────────────────────────────────

    [Fact]
    public async Task TryRedeemAsync_with_wrong_client_returns_ClientMismatch_and_does_not_consume()
    {
        var store = CreateStore();
        const string code = "client-mismatch-code";

        await store.StoreAsync(code, BuildEntry(clientId: "client-a"), CancellationToken.None);

        var mismatch = await store.TryRedeemAsync(code, "client-b", "family-wrong", CancellationToken.None);
        mismatch.Should().BeOfType<AuthorizationCodeRedemptionResult.ClientMismatch>();

        var redeemed = await store.TryRedeemAsync(code, "client-a", "family-correct", CancellationToken.None);
        redeemed.Should().BeOfType<AuthorizationCodeRedemptionResult.Redeemed>(
            because: "ClientMismatch must leave the code intact for the legitimate client");
    }

    // ── Replay / already redeemed ─────────────────────────────────────────────────────────────────

    [Fact]
    public async Task TryRedeemAsync_after_successful_redemption_returns_AlreadyRedeemed_with_original_familyId()
    {
        var store = CreateStore();
        const string code = "replay-code";

        await store.StoreAsync(code, BuildEntry(), CancellationToken.None);
        await store.TryRedeemAsync(code, "client-a", "family-original", CancellationToken.None);

        var replay = await store.TryRedeemAsync(code, "client-a", "family-replay", CancellationToken.None);

        replay.Should().BeOfType<AuthorizationCodeRedemptionResult.AlreadyRedeemed>()
            .Which.FamilyId.Should().Be("family-original");
    }

    // ── Unknown code ──────────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task TryRedeemAsync_for_unknown_code_returns_NotFound()
    {
        var store = CreateStore();

        var outcome = await store.TryRedeemAsync("never-stored", "client-a", "family-1", CancellationToken.None);

        outcome.Should().BeOfType<AuthorizationCodeRedemptionResult.NotFound>();
    }

    // ── Logical expiry: accept-grace direction + ClockSkewTolerance boundary ─────────────────────

    [Fact]
    public async Task TryRedeemAsync_at_ExpiresAt_exactly_is_still_valid_within_tolerance()
    {
        var startTime = new DateTimeOffset(2090, 1, 1, 12, 0, 0, TimeSpan.Zero);
        var tolerance = TimeSpan.FromSeconds(5);
        var expiresAt = startTime.AddMinutes(1);
        var tp = new FakeTimeProvider(startTime);
        var store = CreateStore(
            serverOptions: new AuthorizationServerOptions { ClockSkewTolerance = tolerance },
            timeProvider: tp);
        const string code = "clock-skew-at-expires";

        await store.StoreAsync(code, BuildEntry(issuedAt: startTime, expiresAt: expiresAt), CancellationToken.None);
        tp.Advance(expiresAt - startTime);

        var outcome = await store.TryRedeemAsync(code, "client-a", "family-1", CancellationToken.None);

        outcome.Should().BeOfType<AuthorizationCodeRedemptionResult.Redeemed>(
            because: "now == ExpiresAt is still valid: the check is now >= ExpiresAt + tolerance");
    }

    [Fact]
    public async Task TryRedeemAsync_at_ExpiresAt_plus_tolerance_is_expired()
    {
        var startTime = new DateTimeOffset(2090, 1, 1, 12, 0, 0, TimeSpan.Zero);
        var tolerance = TimeSpan.FromSeconds(5);
        var expiresAt = startTime.AddMinutes(1);
        var tp = new FakeTimeProvider(startTime);
        var store = CreateStore(
            serverOptions: new AuthorizationServerOptions { ClockSkewTolerance = tolerance },
            timeProvider: tp);
        const string code = "clock-skew-boundary";

        await store.StoreAsync(code, BuildEntry(issuedAt: startTime, expiresAt: expiresAt), CancellationToken.None);
        tp.Advance(expiresAt - startTime + tolerance);

        var outcome = await store.TryRedeemAsync(code, "client-a", "family-1", CancellationToken.None);

        outcome.Should().BeOfType<AuthorizationCodeRedemptionResult.NotFound>(
            because: "now == ExpiresAt + tolerance is expired");
    }

    // ── Concurrent redeem race ────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task TryRedeemAsync_exactly_one_Redeemed_under_concurrent_redemption()
    {
        var store = CreateStore();
        const string code = "concurrent-code";
        await store.StoreAsync(code, BuildEntry(), CancellationToken.None);

        const int concurrency = 50;
        using var gate = new SemaphoreSlim(0, concurrency);
        var tasks = Enumerable.Range(0, concurrency)
            .Select(i => Task.Run(async () =>
            {
                await gate.WaitAsync();
                return await store.TryRedeemAsync(code, "client-a", $"family-{i}", CancellationToken.None);
            }))
            .ToArray();

        gate.Release(concurrency);
        var outcomes = await Task.WhenAll(tasks);

        outcomes.Count(o => o is AuthorizationCodeRedemptionResult.Redeemed).Should().Be(1);
        outcomes.Count(o => o is AuthorizationCodeRedemptionResult.AlreadyRedeemed).Should().Be(concurrency - 1);
        outcomes.Count(o => o is AuthorizationCodeRedemptionResult.NotFound).Should().Be(0);
    }

    // ── §7 two-catch-site decrypt asymmetry (pinned independently) ──────────────────────────────

    [Fact]
    public async Task TryRedeemAsync_returns_NotFound_when_entry_cannot_be_unprotected()
    {
        // Simulates DP key rotation: store1 writes with dp1, store2 reads with dp2. No tombstone
        // exists, so this must be NotFound — not AlreadyRedeemed.
        var backingStore = new InMemoryAuthorizationCodeBackingStore();
        var dp1 = new EphemeralDataProtectionProvider();
        var dp2 = new EphemeralDataProtectionProvider();
        var store1 = CreateStore(backingStore: backingStore, dp: dp1);
        var store2 = CreateStore(backingStore: backingStore, dp: dp2);
        const string code = "entry-unreadable-code";

        await store1.StoreAsync(code, BuildEntry(), CancellationToken.None);
        var outcome = await store2.TryRedeemAsync(code, "client-a", "family-1", CancellationToken.None);

        outcome.Should().BeOfType<AuthorizationCodeRedemptionResult.NotFound>(
            because: "§7: an entry that cannot be unprotected is unusable — nothing to hand back");
    }

    [Fact]
    public async Task TryRedeemAsync_returns_AlreadyRedeemed_when_tombstone_ProtectedSecret_cannot_be_unprotected()
    {
        // Simulates DP key rotation on the tombstone's ProtectedSecret: store1 redeems (writing
        // the tombstone under dp1), store2 replays with dp2. FamilyId is plaintext in the
        // envelope, so it must still be recovered even though ProtectedSecret fails to unprotect.
        var backingStore = new InMemoryAuthorizationCodeBackingStore();
        var dp1 = new EphemeralDataProtectionProvider();
        var dp2 = new EphemeralDataProtectionProvider();
        var store1 = CreateStore(backingStore: backingStore, dp: dp1);
        var store2 = CreateStore(backingStore: backingStore, dp: dp2);
        const string code = "tombstone-secret-unreadable-code";

        await store1.StoreAsync(code, BuildEntry(), CancellationToken.None);
        var first = await store1.TryRedeemAsync(code, "client-a", "family-original", CancellationToken.None);
        first.Should().BeOfType<AuthorizationCodeRedemptionResult.Redeemed>();

        var replay = await store2.TryRedeemAsync(code, "client-a", "family-replay", CancellationToken.None);

        replay.Should().BeOfType<AuthorizationCodeRedemptionResult.AlreadyRedeemed>()
            .Which.FamilyId.Should().Be("family-original",
                because: "§7: FamilyId is plaintext and must be recoverable even when " +
                          "ProtectedSecret cannot be unprotected — not the old empty-string sentinel");
    }

    // ── §8 fail-closed: backing-store faults wrap as ZeeKayDaStoreException ─────────────────────

    [Fact]
    public async Task StoreAsync_wraps_backingStore_exception_in_ZeeKayDaStoreException()
    {
        var store = CreateStore(backingStore: new ThrowingBackingStore());

        var act = async () => await store.StoreAsync("code", BuildEntry(), CancellationToken.None);

        var assertion = await act.Should().ThrowAsync<ZeeKayDaStoreException>();
        assertion.Which.InnerException.Should().BeOfType<InvalidOperationException>();
    }

    [Fact]
    public async Task TryRedeemAsync_wraps_backingStore_GetAsync_exception_in_ZeeKayDaStoreException()
    {
        var store = CreateStore(backingStore: new ThrowingBackingStore());

        var act = async () => await store.TryRedeemAsync("code", "client-a", "family-1", CancellationToken.None);

        await act.Should().ThrowAsync<ZeeKayDaStoreException>();
    }

    [Fact]
    public async Task StoreAsync_throws_ZeeKayDaStoreException_when_the_handle_collides_with_an_existing_entry()
    {
        var store = CreateStore(backingStore: new AlwaysCollidingBackingStore());

        var act = async () => await store.StoreAsync("code", BuildEntry(), CancellationToken.None);

        await act.Should().ThrowAsync<ZeeKayDaStoreException>(
            because: "handles are 256-bit random, so a physically-present key at StoreAsync time is a genuine anomaly");
    }

    [Fact]
    public async Task TryRedeemAsync_loses_tombstone_insert_race_resolves_via_the_winners_tombstone()
    {
        // Simulates two concurrent redeemers: the decorator writes the SAME envelope another
        // "winner" would have written, then reports the insert as lost, exercising the §9
        // "if it returns false, someone else won the race, resolve via the tombstone" path
        // deterministically rather than relying on real thread contention.
        var inner = new InMemoryAuthorizationCodeBackingStore();
        var dp = new EphemeralDataProtectionProvider();
        var seedStore = CreateStore(backingStore: inner, dp: dp);
        const string code = "race-losing-code";
        await seedStore.StoreAsync(code, BuildEntry(), CancellationToken.None);

        var racingStore = CreateStore(backingStore: new RaceLosingBackingStore(inner), dp: dp);

        var outcome = await racingStore.TryRedeemAsync(code, "client-a", "family-raced", CancellationToken.None);

        outcome.Should().BeOfType<AuthorizationCodeRedemptionResult.AlreadyRedeemed>()
            .Which.FamilyId.Should().Be("family-raced");
    }

    [Fact]
    public async Task TryRedeemAsync_wraps_corrupted_tombstone_bytes_in_ZeeKayDaStoreException()
    {
        var store = CreateStore(backingStore: new CorruptTombstoneBackingStore());

        var act = async () => await store.TryRedeemAsync("no-entry-code", "client-a", "family-1", CancellationToken.None);

        await act.Should().ThrowAsync<ZeeKayDaStoreException>(
            because: "a corrupted tombstone envelope is a genuine data-integrity fault, not a DP-rotation outcome");
    }

    [Fact]
    public async Task StoreAsync_wraps_DataProtection_Protect_failure_in_ZeeKayDaStoreException()
    {
        var faultingDp = new ProtectFailingDataProtectionProvider(new EphemeralDataProtectionProvider());
        var store = CreateStore(dp: faultingDp);

        var act = async () => await store.StoreAsync("code", BuildEntry(), CancellationToken.None);

        await act.Should().ThrowAsync<ZeeKayDaStoreException>();
    }

    [Fact]
    public async Task TryRedeemAsync_wraps_tombstone_Protect_failure_in_ZeeKayDaStoreException()
    {
        var workingDp = new EphemeralDataProtectionProvider();
        var backingStore = new InMemoryAuthorizationCodeBackingStore();
        var seedStore = CreateStore(backingStore: backingStore, dp: workingDp);
        const string code = "protect-failure-code";
        await seedStore.StoreAsync(code, BuildEntry(), CancellationToken.None);

        var store = CreateStore(backingStore: backingStore, dp: new ProtectFailingDataProtectionProvider(workingDp));

        var act = async () => await store.TryRedeemAsync(code, "client-a", "family-1", CancellationToken.None);

        await act.Should().ThrowAsync<ZeeKayDaStoreException>();
    }

    [Fact]
    public async Task TryRedeemAsync_wraps_backingStore_RemoveAsync_exception_in_ZeeKayDaStoreException()
    {
        var store = CreateStore(backingStore: new ThrowingOnRemoveBackingStore());
        await store.StoreAsync("code", BuildEntry(), CancellationToken.None);

        var act = async () => await store.TryRedeemAsync("code", "client-a", "family-1", CancellationToken.None);

        await act.Should().ThrowAsync<ZeeKayDaStoreException>();
    }

    [Fact]
    public async Task TryRedeemAsync_rethrows_OperationCanceledException_from_RemoveAsync_unwrapped()
    {
        var store = CreateStore(backingStore: new CancellationThrowingOnRemoveBackingStore());
        await store.StoreAsync("code", BuildEntry(), CancellationToken.None);

        var act = async () => await store.TryRedeemAsync("code", "client-a", "family-1", CancellationToken.None);

        await act.Should().ThrowAsync<OperationCanceledException>();
    }

    // ── Sealing member (ADR 0013 §1) ─────────────────────────────────────────────────────────────

    [Fact]
    public void SealAsFrameworkOwnedProtocol_can_be_invoked_through_the_interface_without_throwing()
    {
        IAuthorizationCodeStore store = CreateStore();

        var act = () => store.SealAsFrameworkOwnedProtocol();

        act.Should().NotThrow();
    }

    // ── §8 cancellation is not a store fault ──────────────────────────────────────────────────────

    [Fact]
    public async Task StoreAsync_rethrows_OperationCanceledException_unwrapped()
    {
        var store = CreateStore();
        using var cts = new CancellationTokenSource();
        cts.Cancel();

        var act = async () => await store.StoreAsync("code", BuildEntry(), cts.Token);

        await act.Should().ThrowAsync<OperationCanceledException>();
    }

    [Fact]
    public async Task TryRedeemAsync_rethrows_OperationCanceledException_unwrapped_not_as_ZeeKayDaStoreException()
    {
        var store = CreateStore(backingStore: new CancellationThrowingBackingStore());

        var act = async () => await store.TryRedeemAsync("code", "client-a", "family-1", CancellationToken.None);

        await act.Should().ThrowAsync<OperationCanceledException>(
            because: "Guarded(...) must rethrow OperationCanceledException unwrapped, not classify it as a store fault");
    }

    // ── Argument guards ───────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task StoreAsync_throws_ArgumentNullException_for_null_code()
    {
        var store = CreateStore();

        var act = async () => await store.StoreAsync(null!, BuildEntry(), CancellationToken.None);

        await act.Should().ThrowAsync<ArgumentNullException>();
    }

    [Fact]
    public async Task TryRedeemAsync_throws_ArgumentNullException_for_null_familyId()
    {
        var store = CreateStore();

        var act = async () => await store.TryRedeemAsync("code", "client-a", null!, CancellationToken.None);

        await act.Should().ThrowAsync<ArgumentNullException>();
    }

    // ── Helpers ───────────────────────────────────────────────────────────────────────────────────

    private sealed class ThrowingBackingStore : IAuthorizationCodeBackingStore
    {
        public ValueTask<bool> TryInsertAsync(StoreKey key, ReadOnlyMemory<byte> value, DateTimeOffset expiresAt, CancellationToken cancellationToken)
            => throw new InvalidOperationException("Simulated backing store failure.");

        public ValueTask<ReadOnlyMemory<byte>?> GetAsync(StoreKey key, CancellationToken cancellationToken)
            => throw new InvalidOperationException("Simulated backing store failure.");

        public ValueTask RemoveAsync(StoreKey key, CancellationToken cancellationToken)
            => throw new InvalidOperationException("Simulated backing store failure.");
    }

    private sealed class CancellationThrowingBackingStore : IAuthorizationCodeBackingStore
    {
        public ValueTask<bool> TryInsertAsync(StoreKey key, ReadOnlyMemory<byte> value, DateTimeOffset expiresAt, CancellationToken cancellationToken)
            => throw new OperationCanceledException();

        public ValueTask<ReadOnlyMemory<byte>?> GetAsync(StoreKey key, CancellationToken cancellationToken)
            => throw new OperationCanceledException();

        public ValueTask RemoveAsync(StoreKey key, CancellationToken cancellationToken)
            => throw new OperationCanceledException();
    }

    private sealed class AlwaysCollidingBackingStore : IAuthorizationCodeBackingStore
    {
        public ValueTask<bool> TryInsertAsync(StoreKey key, ReadOnlyMemory<byte> value, DateTimeOffset expiresAt, CancellationToken cancellationToken)
            => ValueTask.FromResult(false);

        public ValueTask<ReadOnlyMemory<byte>?> GetAsync(StoreKey key, CancellationToken cancellationToken)
            => ValueTask.FromResult<ReadOnlyMemory<byte>?>(null);

        public ValueTask RemoveAsync(StoreKey key, CancellationToken cancellationToken)
            => ValueTask.CompletedTask;
    }

    /// <summary>
    /// Wraps a real backing store; on <see cref="TryInsertAsync"/> it writes the caller's own
    /// value first (as if another concurrent redeemer had just won) and then reports the insert
    /// as lost, deterministically exercising the §9 "someone else won the race" path.
    /// </summary>
    private sealed class RaceLosingBackingStore : IAuthorizationCodeBackingStore
    {
        private readonly IAuthorizationCodeBackingStore _inner;

        public RaceLosingBackingStore(IAuthorizationCodeBackingStore inner) => _inner = inner;

        public async ValueTask<bool> TryInsertAsync(StoreKey key, ReadOnlyMemory<byte> value, DateTimeOffset expiresAt, CancellationToken cancellationToken)
        {
            await _inner.TryInsertAsync(key, value, expiresAt, cancellationToken).ConfigureAwait(false);
            return false;
        }

        public ValueTask<ReadOnlyMemory<byte>?> GetAsync(StoreKey key, CancellationToken cancellationToken)
            => _inner.GetAsync(key, cancellationToken);

        public ValueTask RemoveAsync(StoreKey key, CancellationToken cancellationToken)
            => _inner.RemoveAsync(key, cancellationToken);
    }

    private sealed class CorruptTombstoneBackingStore : IAuthorizationCodeBackingStore
    {
        public ValueTask<bool> TryInsertAsync(StoreKey key, ReadOnlyMemory<byte> value, DateTimeOffset expiresAt, CancellationToken cancellationToken)
            => ValueTask.FromResult(true);

        public ValueTask<ReadOnlyMemory<byte>?> GetAsync(StoreKey key, CancellationToken cancellationToken)
        {
            var isTombstone = key.ToString().Contains(":t:", StringComparison.Ordinal);
            return ValueTask.FromResult(isTombstone ? (ReadOnlyMemory<byte>?)new byte[] { 0x00, 0x01, 0x02 } : null);
        }

        public ValueTask RemoveAsync(StoreKey key, CancellationToken cancellationToken)
            => ValueTask.CompletedTask;
    }

    private sealed class ThrowingOnRemoveBackingStore : IAuthorizationCodeBackingStore
    {
        private readonly IAuthorizationCodeBackingStore _inner = new InMemoryAuthorizationCodeBackingStore();

        public ValueTask<bool> TryInsertAsync(StoreKey key, ReadOnlyMemory<byte> value, DateTimeOffset expiresAt, CancellationToken cancellationToken)
            => _inner.TryInsertAsync(key, value, expiresAt, cancellationToken);

        public ValueTask<ReadOnlyMemory<byte>?> GetAsync(StoreKey key, CancellationToken cancellationToken)
            => _inner.GetAsync(key, cancellationToken);

        public ValueTask RemoveAsync(StoreKey key, CancellationToken cancellationToken)
            => throw new InvalidOperationException("Simulated backing store Remove failure.");
    }

    private sealed class CancellationThrowingOnRemoveBackingStore : IAuthorizationCodeBackingStore
    {
        private readonly IAuthorizationCodeBackingStore _inner = new InMemoryAuthorizationCodeBackingStore();

        public ValueTask<bool> TryInsertAsync(StoreKey key, ReadOnlyMemory<byte> value, DateTimeOffset expiresAt, CancellationToken cancellationToken)
            => _inner.TryInsertAsync(key, value, expiresAt, cancellationToken);

        public ValueTask<ReadOnlyMemory<byte>?> GetAsync(StoreKey key, CancellationToken cancellationToken)
            => _inner.GetAsync(key, cancellationToken);

        public ValueTask RemoveAsync(StoreKey key, CancellationToken cancellationToken)
            => throw new OperationCanceledException();
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

