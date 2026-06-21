using System.Buffers.Text;
using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Time.Testing;
using ZeeKayDa.Auth.Stores;

namespace ZeeKayDa.Auth.Tests.Stores;

/// <summary>
/// Tests for <see cref="DistributedCacheRefreshTokenStore"/> covering all acceptance criteria.
/// </summary>
/// <remarks>
/// Uses <see cref="MemoryDistributedCache"/> as the backing store so tests are self-contained
/// and fast. IO failures are simulated via a <see cref="FaultingDistributedCache"/> delegate wrapper.
/// </remarks>
public sealed class DistributedCacheRefreshTokenStoreTests
{
    /// <summary>
    /// A far-future date used as ExpiresAt so entries are never evicted by the real clock.
    /// </summary>
    private static readonly DateTimeOffset FarFuture = new(2099, 1, 1, 0, 0, 0, TimeSpan.Zero);

    // ── Factory helpers ───────────────────────────────────────────────────────────────────────────

    private static DistributedCacheRefreshTokenStore CreateStore(
        IDistributedCache? cache = null,
        IDataProtectionProvider? dp = null,
        AuthorizationServerOptions? serverOptions = null,
        TimeProvider? timeProvider = null)
    {
        return new DistributedCacheRefreshTokenStore(
            cache ?? CreateMemoryDistributedCache(),
            dp ?? new EphemeralDataProtectionProvider(),
            new OptionsWrapper<AuthorizationServerOptions>(serverOptions ?? new AuthorizationServerOptions()),
            timeProvider ?? TimeProvider.System);
    }

    private static IDistributedCache CreateMemoryDistributedCache()
        => new MemoryDistributedCache(
            new OptionsWrapper<MemoryDistributedCacheOptions>(new MemoryDistributedCacheOptions()));

    private static RefreshTokenEntry BuildEntry(
        string clientId = "client-a",
        string familyId = "family-1",
        string sub = "user-1",
        DateTimeOffset? issuedAt = null,
        DateTimeOffset? expiresAt = null,
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
            PreviousTokenHandleHash = previousTokenHandleHash,
        };

    private static string ComputeExpectedHashedSegment(string handle)
    {
        var inputBytes = Encoding.UTF8.GetBytes(handle);
        var hash = SHA256.HashData(inputBytes);
        return Base64Url.EncodeToString(hash);
    }

    private static string BuildExpectedCacheKey(string handle)
        => $"zkd:rt:{ComputeExpectedHashedSegment(handle)}";

    private static string BuildExpectedRevocationMarkerKey(string familyId)
        => $"zkd:rt:family:{ComputeExpectedHashedSegment(familyId)}:revoked";

    // ── AC 1 — StoreAsync then FindAsync → returns entry ─────────────────────────────────────────

    [Fact]
    public async Task StoreAsync_then_FindAsync_returns_stored_entry()
    {
        var store = CreateStore();
        const string handle = "find-round-trip";
        var entry = BuildEntry(clientId: "client-a", familyId: "fam-1");

        await store.StoreAsync(handle, entry, CancellationToken.None);
        var result = await store.FindAsync(handle, CancellationToken.None);

        result.Should().NotBeNull(because: "a stored, unexpired, unconsumed entry must be found");
        result.Should().BeEquivalentTo(entry,
            because: "the returned entry must match the stored entry exactly");
    }

    // ── AC 2 — StoreAsync then TryConsumeAsync with correct client → Consumed ───────────────────

    [Fact]
    public async Task StoreAsync_then_TryConsumeAsync_with_correct_client_returns_Consumed()
    {
        var store = CreateStore();
        const string handle = "valid-consume";
        var entry = BuildEntry(clientId: "client-a");

        await store.StoreAsync(handle, entry, CancellationToken.None);
        var outcome = await store.TryConsumeAsync(handle, "client-a", CancellationToken.None);

        outcome.Should().BeOfType<RefreshTokenConsumptionOutcome.Consumed>(
            because: "a valid token presented by the correct client must be consumed");
    }

    [Fact]
    public async Task TryConsumeAsync_Consumed_entry_matches_stored_entry()
    {
        var store = CreateStore();
        const string handle = "round-trip-handle";
        var now = DateTimeOffset.UtcNow;
        var entry = BuildEntry(clientId: "client-a", familyId: "fam-roundtrip", issuedAt: now, expiresAt: FarFuture);

        await store.StoreAsync(handle, entry, CancellationToken.None);
        var outcome = await store.TryConsumeAsync(handle, "client-a", CancellationToken.None);

        outcome.Should().BeOfType<RefreshTokenConsumptionOutcome.Consumed>()
            .Which.Entry.Should().BeEquivalentTo(entry,
            because: "the consumed entry must match the stored entry exactly");
    }

    // ── AC 3 — TryConsumeAsync after consumption → AlreadyConsumed with FamilyId ────────────────

    [Fact]
    public async Task TryConsumeAsync_after_consumption_returns_AlreadyConsumed()
    {
        var store = CreateStore();
        const string handle = "replay-attack-handle";

        await store.StoreAsync(handle, BuildEntry(), CancellationToken.None);
        await store.TryConsumeAsync(handle, "client-a", CancellationToken.None);

        var replayOutcome = await store.TryConsumeAsync(handle, "client-a", CancellationToken.None);

        replayOutcome.Should().BeOfType<RefreshTokenConsumptionOutcome.AlreadyConsumed>(
            because: "a replayed token handle must return AlreadyConsumed, not NotFound");
    }

    [Fact]
    public async Task TryConsumeAsync_AlreadyConsumed_carries_correct_family_id()
    {
        var store = CreateStore();
        const string handle = "family-id-in-tombstone";
        const string familyId = "fam-original";

        await store.StoreAsync(handle, BuildEntry(familyId: familyId), CancellationToken.None);
        await store.TryConsumeAsync(handle, "client-a", CancellationToken.None);

        var replayOutcome = await store.TryConsumeAsync(handle, "client-a", CancellationToken.None);

        replayOutcome.Should().BeOfType<RefreshTokenConsumptionOutcome.AlreadyConsumed>()
            .Which.FamilyId.Should().Be(familyId,
            because: "the tombstone must preserve the family ID for the replay detection signal");
    }

    // ── AC 4 — FindAsync after consumption → null (IsConsumed tombstone) ─────────────────────────

    [Fact]
    public async Task FindAsync_returns_null_after_TryConsumeAsync_succeeds()
    {
        var store = CreateStore();
        const string handle = "find-after-consume";

        await store.StoreAsync(handle, BuildEntry(), CancellationToken.None);
        await store.TryConsumeAsync(handle, "client-a", CancellationToken.None);

        var result = await store.FindAsync(handle, CancellationToken.None);

        result.Should().BeNull(because: "a consumed token (IsConsumed tombstone in place) must return null from FindAsync");
    }

    // ── AC 5 — TryConsumeAsync with wrong client → ClientMismatch (NOT consumed) ─────────────────

    [Fact]
    public async Task TryConsumeAsync_with_wrong_client_returns_ClientMismatch()
    {
        var store = CreateStore();
        const string handle = "client-mismatch-handle";

        await store.StoreAsync(handle, BuildEntry(clientId: "client-a"), CancellationToken.None);

        var outcome = await store.TryConsumeAsync(handle, "client-b", CancellationToken.None);

        outcome.Should().BeOfType<RefreshTokenConsumptionOutcome.ClientMismatch>(
            because: "presenting client does not match the client the token is bound to");
    }

    [Fact]
    public async Task TryConsumeAsync_ClientMismatch_does_not_consume_token_allowing_legitimate_client_to_succeed()
    {
        var store = CreateStore();
        const string handle = "client-mismatch-no-consume";

        await store.StoreAsync(handle, BuildEntry(clientId: "client-a"), CancellationToken.None);

        var mismatchOutcome = await store.TryConsumeAsync(handle, "client-b", CancellationToken.None);
        mismatchOutcome.Should().BeOfType<RefreshTokenConsumptionOutcome.ClientMismatch>(
            because: "presenting client does not match the bound client");

        var legitimateOutcome = await store.TryConsumeAsync(handle, "client-a", CancellationToken.None);
        legitimateOutcome.Should().BeOfType<RefreshTokenConsumptionOutcome.Consumed>(
            because: "ClientMismatch must leave the token intact for the legitimate client");
    }

    // ── AC 6 — TryConsumeAsync for expired entry → NotFound ──────────────────────────────────────

    [Fact]
    public async Task TryConsumeAsync_returns_NotFound_for_expired_entry()
    {
        var startTime = new DateTimeOffset(2090, 1, 1, 12, 0, 0, TimeSpan.Zero);
        var expiresAt = startTime.AddMinutes(1);

        var tp = new FakeTimeProvider(startTime);
        var store = CreateStore(timeProvider: tp);
        const string handle = "consume-expiry-check";
        var entry = BuildEntry(issuedAt: startTime, expiresAt: expiresAt);

        await store.StoreAsync(handle, entry, CancellationToken.None);
        tp.Advance(TimeSpan.FromMinutes(2));

        var outcome = await store.TryConsumeAsync(handle, "client-a", CancellationToken.None);

        outcome.Should().BeOfType<RefreshTokenConsumptionOutcome.NotFound>(
            because: "TryConsumeAsync must use TimeProvider.GetUtcNow() to check logical expiry");
    }

    // ── AC 7 — FindAsync for expired entry → null ─────────────────────────────────────────────────

    [Fact]
    public async Task FindAsync_returns_null_for_expired_entry()
    {
        var startTime = new DateTimeOffset(2090, 1, 1, 12, 0, 0, TimeSpan.Zero);
        var expiresAt = startTime.AddMinutes(1);

        var tp = new FakeTimeProvider(startTime);
        var store = CreateStore(timeProvider: tp);
        const string handle = "find-expiry-check";
        var entry = BuildEntry(issuedAt: startTime, expiresAt: expiresAt);

        await store.StoreAsync(handle, entry, CancellationToken.None);
        tp.Advance(TimeSpan.FromMinutes(2));

        var result = await store.FindAsync(handle, CancellationToken.None);

        result.Should().BeNull(
            because: "FindAsync must use TimeProvider.GetUtcNow() to check logical expiry");
    }

    // ── AC 8 — RevokeFamilyAsync then FindAsync → null ───────────────────────────────────────────

    [Fact]
    public async Task RevokeFamilyAsync_then_FindAsync_returns_null()
    {
        var store = CreateStore();
        const string handle = "revoked-family-find";
        const string familyId = "family-to-revoke";

        await store.StoreAsync(handle, BuildEntry(familyId: familyId), CancellationToken.None);
        await store.RevokeFamilyAsync(familyId, CancellationToken.None);

        var result = await store.FindAsync(handle, CancellationToken.None);

        result.Should().BeNull(
            because: "FindAsync must return null for tokens whose family has been revoked");
    }

    // ── AC 9 — RevokeFamilyAsync then TryConsumeAsync → Revoked ─────────────────────────────────

    [Fact]
    public async Task RevokeFamilyAsync_then_TryConsumeAsync_returns_Revoked()
    {
        var store = CreateStore();
        const string handle = "revoked-family-consume";
        const string familyId = "fam-revoked";

        await store.StoreAsync(handle, BuildEntry(familyId: familyId), CancellationToken.None);
        await store.RevokeFamilyAsync(familyId, CancellationToken.None);

        var outcome = await store.TryConsumeAsync(handle, "client-a", CancellationToken.None);

        outcome.Should().BeOfType<RefreshTokenConsumptionOutcome.Revoked>(
            because: "TryConsumeAsync must return Revoked for tokens in a revoked family");
    }

    [Fact]
    public async Task TryConsumeAsync_Revoked_carries_correct_family_id()
    {
        var store = CreateStore();
        const string handle = "revoked-family-id-check";
        const string familyId = "fam-with-id";

        await store.StoreAsync(handle, BuildEntry(familyId: familyId), CancellationToken.None);
        await store.RevokeFamilyAsync(familyId, CancellationToken.None);

        var outcome = await store.TryConsumeAsync(handle, "client-a", CancellationToken.None);

        outcome.Should().BeOfType<RefreshTokenConsumptionOutcome.Revoked>()
            .Which.FamilyId.Should().Be(familyId,
            because: "the Revoked outcome must carry the family ID from the token entry");
    }

    // ── AC 10 — RevokeFamilyAsync is idempotent ───────────────────────────────────────────────────

    [Fact]
    public async Task RevokeFamilyAsync_is_idempotent()
    {
        var store = CreateStore();
        const string familyId = "idempotent-family";

        await store.RevokeFamilyAsync(familyId, CancellationToken.None);
        var act = async () => await store.RevokeFamilyAsync(familyId, CancellationToken.None);

        await act.Should().NotThrowAsync(
            because: "RevokeFamilyAsync must be idempotent — calling it twice must not throw");
    }

    [Fact]
    public async Task RevokeFamilyAsync_with_unknown_family_id_does_not_throw()
    {
        var store = CreateStore();

        var act = async () =>
            await store.RevokeFamilyAsync("completely-unknown-family", CancellationToken.None);

        await act.Should().NotThrowAsync(
            because: "revoking an unknown family ID is a valid idempotent no-op");
    }

    // ── StoreAsync with already-expired entry → ZeeKayDaStoreException ───────────────────────────

    [Fact]
    public async Task StoreAsync_throws_ZeeKayDaStoreException_for_already_expired_entry()
    {
        var startTime = new DateTimeOffset(2090, 1, 1, 12, 0, 0, TimeSpan.Zero);
        var tp = new FakeTimeProvider(startTime);
        var store = CreateStore(timeProvider: tp);

        // Entry that expired one second before now
        var entry = BuildEntry(expiresAt: startTime.AddSeconds(-1));

        var act = async () =>
            await store.StoreAsync("expired-handle", entry, CancellationToken.None);

        await act.Should().ThrowAsync<ZeeKayDaStoreException>(
            because: "storing an already-expired entry must be rejected to prevent silent TTL clamping");
    }

    // ── AC 11 — IO failure on StoreAsync → ZeeKayDaStoreException ───────────────────────────────

    [Fact]
    public async Task StoreAsync_wraps_distributed_cache_exception_in_ZeeKayDaStoreException()
    {
        var faultingCache = new FaultingDistributedCache(
            CreateMemoryDistributedCache(),
            throwOnSet: true);
        var store = CreateStore(cache: faultingCache);

        var act = async () =>
            await store.StoreAsync("any-handle", BuildEntry(), CancellationToken.None);

        var assertion = await act.Should().ThrowAsync<ZeeKayDaStoreException>(
            because: "IO failures from IDistributedCache must be wrapped in ZeeKayDaStoreException");
        assertion.Which.InnerException.Should().BeOfType<InvalidOperationException>(
            because: "the original exception must be preserved as InnerException");
    }

    [Fact]
    public async Task StoreAsync_ZeeKayDaStoreException_has_descriptive_message()
    {
        var faultingCache = new FaultingDistributedCache(
            CreateMemoryDistributedCache(),
            throwOnSet: true);
        var store = CreateStore(cache: faultingCache);

        var exception = await Assert.ThrowsAsync<ZeeKayDaStoreException>(
            () => store.StoreAsync("handle", BuildEntry(), CancellationToken.None));

        exception.Message.Should().NotBeNullOrWhiteSpace(
            because: "ZeeKayDaStoreException must carry a descriptive message");
    }

    // ── AC 12 — IO failure on FindAsync (entry read) → ZeeKayDaStoreException ───────────────────

    [Fact]
    public async Task FindAsync_wraps_entry_read_IO_failure_in_ZeeKayDaStoreException()
    {
        var faultingCache = new FaultingDistributedCache(
            CreateMemoryDistributedCache(),
            throwOnGet: true);
        var store = CreateStore(cache: faultingCache);

        var act = async () =>
            await store.FindAsync("some-handle", CancellationToken.None);

        await act.Should().ThrowAsync<ZeeKayDaStoreException>(
            because: "IO failure reading the entry in FindAsync must be wrapped in ZeeKayDaStoreException");
    }

    // ── AC 13 — IO failure on FindAsync revocation marker read → ZeeKayDaStoreException ──────────

    [Fact]
    public async Task FindAsync_wraps_revocation_marker_read_IO_failure_in_ZeeKayDaStoreException()
    {
        var innerCache = CreateMemoryDistributedCache();

        // Share the same DP provider so the reading store can decrypt what the writing store stored
        var sharedDp = new EphemeralDataProtectionProvider();

        // Write the entry successfully
        var writeStore = CreateStore(cache: innerCache, dp: sharedDp);
        await writeStore.StoreAsync("handle-marker-read-fail", BuildEntry(), CancellationToken.None);

        // First Get (entry read) succeeds; second Get (revocation marker read) throws
        var faultingCache = new FaultingDistributedCache(innerCache, throwOnGetAfterNthCall: 2);
        var store = CreateStore(cache: faultingCache, dp: sharedDp);

        var act = async () =>
            await store.FindAsync("handle-marker-read-fail", CancellationToken.None);

        await act.Should().ThrowAsync<ZeeKayDaStoreException>(
            because: "IO failure reading the revocation marker in FindAsync must be wrapped in ZeeKayDaStoreException");
    }

    // ── AC 14 — IO failure on TryConsumeAsync (entry read) → ZeeKayDaStoreException ─────────────

    [Fact]
    public async Task TryConsumeAsync_wraps_entry_read_IO_failure_in_ZeeKayDaStoreException()
    {
        var faultingCache = new FaultingDistributedCache(
            CreateMemoryDistributedCache(),
            throwOnGet: true);
        var store = CreateStore(cache: faultingCache);

        var act = async () =>
            await store.TryConsumeAsync("some-handle", "client-a", CancellationToken.None);

        await act.Should().ThrowAsync<ZeeKayDaStoreException>(
            because: "IO failure reading the entry in TryConsumeAsync must be wrapped in ZeeKayDaStoreException");
    }

    // ── AC 15 — IO failure on TryConsumeAsync (marker read) → ZeeKayDaStoreException ─────────────

    [Fact]
    public async Task TryConsumeAsync_wraps_revocation_marker_read_IO_failure_in_ZeeKayDaStoreException()
    {
        var innerCache = CreateMemoryDistributedCache();

        // Share the same DP provider so the reading store can decrypt what the writing store stored
        var sharedDp = new EphemeralDataProtectionProvider();

        var writeStore = CreateStore(cache: innerCache, dp: sharedDp);
        await writeStore.StoreAsync("handle-rt-marker-fail", BuildEntry(), CancellationToken.None);

        // First Get (entry read) succeeds; second Get (revocation marker read) throws
        var faultingCache = new FaultingDistributedCache(innerCache, throwOnGetAfterNthCall: 2);
        var store = CreateStore(cache: faultingCache, dp: sharedDp);

        var act = async () =>
            await store.TryConsumeAsync("handle-rt-marker-fail", "client-a", CancellationToken.None);

        await act.Should().ThrowAsync<ZeeKayDaStoreException>(
            because: "IO failure reading the revocation marker in TryConsumeAsync must be wrapped in ZeeKayDaStoreException");
    }

    // ── AC 16 — IO failure on TryConsumeAsync (tombstone write) → ZeeKayDaStoreException ─────────

    [Fact]
    public async Task TryConsumeAsync_wraps_tombstone_write_IO_failure_in_ZeeKayDaStoreException()
    {
        var innerCache = CreateMemoryDistributedCache();

        // Share the same DP provider so the reading store can decrypt what the writing store stored
        var sharedDp = new EphemeralDataProtectionProvider();

        var writeStore = CreateStore(cache: innerCache, dp: sharedDp);
        await writeStore.StoreAsync("handle-tombstone-write-fail", BuildEntry(), CancellationToken.None);

        // Gets succeed so we reach the tombstone write step; Set throws
        var faultingCache = new FaultingDistributedCache(innerCache, throwOnSet: true);
        var store = CreateStore(cache: faultingCache, dp: sharedDp);

        var act = async () =>
            await store.TryConsumeAsync("handle-tombstone-write-fail", "client-a", CancellationToken.None);

        await act.Should().ThrowAsync<ZeeKayDaStoreException>(
            because: "IO failure writing the consumed tombstone must be wrapped in ZeeKayDaStoreException");
    }

    // ── AC 17 — IO failure on RevokeFamilyAsync → ZeeKayDaStoreException ────────────────────────

    [Fact]
    public async Task RevokeFamilyAsync_wraps_distributed_cache_exception_in_ZeeKayDaStoreException()
    {
        var faultingCache = new FaultingDistributedCache(
            CreateMemoryDistributedCache(),
            throwOnSet: true);
        var store = CreateStore(cache: faultingCache);

        var act = async () =>
            await store.RevokeFamilyAsync("some-family", CancellationToken.None);

        await act.Should().ThrowAsync<ZeeKayDaStoreException>(
            because: "IO failures from IDistributedCache in RevokeFamilyAsync must be wrapped in ZeeKayDaStoreException");
    }

    // ── AC 18 — Entry decryption failure in FindAsync → null ─────────────────────────────────────

    [Fact]
    public async Task FindAsync_returns_null_when_entry_cannot_be_unprotected()
    {
        // Two stores share the same cache but use independent key rings.
        // Store1 writes the entry encrypted under dp1. Store2 uses dp2 — cannot decrypt.
        var sharedCache = CreateMemoryDistributedCache();
        var dp1 = new EphemeralDataProtectionProvider();
        var dp2 = new EphemeralDataProtectionProvider();

        var store1 = CreateStore(cache: sharedCache, dp: dp1);
        var store2 = CreateStore(cache: sharedCache, dp: dp2);
        const string handle = "dp-rotation-find";

        await store1.StoreAsync(handle, BuildEntry(), CancellationToken.None);

        var result = await store2.FindAsync(handle, CancellationToken.None);

        result.Should().BeNull(
            because: "a DP unprotect failure during FindAsync must return null, not throw");
    }

    // ── AC 19 — Entry decryption failure in TryConsumeAsync → NotFound ───────────────────────────

    [Fact]
    public async Task TryConsumeAsync_returns_NotFound_when_entry_cannot_be_unprotected()
    {
        var sharedCache = CreateMemoryDistributedCache();
        var dp1 = new EphemeralDataProtectionProvider();
        var dp2 = new EphemeralDataProtectionProvider();

        var store1 = CreateStore(cache: sharedCache, dp: dp1);
        var store2 = CreateStore(cache: sharedCache, dp: dp2);
        const string handle = "dp-rotation-consume-entry-unreadable";

        await store1.StoreAsync(handle, BuildEntry(), CancellationToken.None);

        // store2 uses dp2 — entry exists in cache but Unprotect will throw CryptographicException
        var outcome = await store2.TryConsumeAsync(handle, "client-a", CancellationToken.None);

        outcome.Should().BeOfType<RefreshTokenConsumptionOutcome.NotFound>(
            because: "an entry that cannot be unprotected (DP key rotation) must return NotFound — " +
                     "no tombstone exists so this is not a detected replay");
    }

    // ── AC 20 — Null argument guards on constructor and methods ──────────────────────────────────

    [Fact]
    public void Constructor_throws_ArgumentNullException_for_null_cache()
    {
        var act = () => new DistributedCacheRefreshTokenStore(
            null!,
            new EphemeralDataProtectionProvider(),
            new OptionsWrapper<AuthorizationServerOptions>(new AuthorizationServerOptions()),
            TimeProvider.System);

        act.Should().Throw<ArgumentNullException>(
            because: "null IDistributedCache must be rejected at construction time");
    }

    [Fact]
    public void Constructor_throws_ArgumentNullException_for_null_dataProtectionProvider()
    {
        var act = () => new DistributedCacheRefreshTokenStore(
            CreateMemoryDistributedCache(),
            null!,
            new OptionsWrapper<AuthorizationServerOptions>(new AuthorizationServerOptions()),
            TimeProvider.System);

        act.Should().Throw<ArgumentNullException>(
            because: "null IDataProtectionProvider must be rejected at construction time");
    }

    [Fact]
    public void Constructor_throws_ArgumentNullException_for_null_serverOptions()
    {
        var act = () => new DistributedCacheRefreshTokenStore(
            CreateMemoryDistributedCache(),
            new EphemeralDataProtectionProvider(),
            null!,
            TimeProvider.System);

        act.Should().Throw<ArgumentNullException>(
            because: "null serverOptions must be rejected at construction time");
    }

    [Fact]
    public void Constructor_throws_ArgumentNullException_for_null_timeProvider()
    {
        var act = () => new DistributedCacheRefreshTokenStore(
            CreateMemoryDistributedCache(),
            new EphemeralDataProtectionProvider(),
            new OptionsWrapper<AuthorizationServerOptions>(new AuthorizationServerOptions()),
            null!);

        act.Should().Throw<ArgumentNullException>(
            because: "null TimeProvider must be rejected at construction time");
    }

    [Fact]
    public async Task StoreAsync_throws_ArgumentNullException_for_null_tokenHandle()
    {
        var store = CreateStore();

        var act = async () =>
            await store.StoreAsync(null!, BuildEntry(), CancellationToken.None);

        await act.Should().ThrowAsync<ArgumentNullException>();
    }

    [Fact]
    public async Task StoreAsync_throws_ArgumentNullException_for_null_entry()
    {
        var store = CreateStore();

        var act = async () =>
            await store.StoreAsync("handle", null!, CancellationToken.None);

        await act.Should().ThrowAsync<ArgumentNullException>();
    }

    [Fact]
    public async Task FindAsync_throws_ArgumentNullException_for_null_tokenHandle()
    {
        var store = CreateStore();

        var act = async () =>
            await store.FindAsync(null!, CancellationToken.None);

        await act.Should().ThrowAsync<ArgumentNullException>();
    }

    [Fact]
    public async Task TryConsumeAsync_throws_ArgumentNullException_for_null_tokenHandle()
    {
        var store = CreateStore();

        var act = async () =>
            await store.TryConsumeAsync(null!, "client-a", CancellationToken.None);

        await act.Should().ThrowAsync<ArgumentNullException>();
    }

    [Fact]
    public async Task TryConsumeAsync_throws_ArgumentNullException_for_null_clientId()
    {
        var store = CreateStore();

        var act = async () =>
            await store.TryConsumeAsync("handle", null!, CancellationToken.None);

        await act.Should().ThrowAsync<ArgumentNullException>();
    }

    [Fact]
    public async Task RevokeFamilyAsync_throws_ArgumentNullException_for_null_familyId()
    {
        var store = CreateStore();

        var act = async () =>
            await store.RevokeFamilyAsync(null!, CancellationToken.None);

        await act.Should().ThrowAsync<ArgumentNullException>();
    }

    // ── CancellationToken propagation ─────────────────────────────────────────────────────────────
    // Note: MemoryDistributedCache does not honour CancellationToken for in-memory operations.
    // To test that the store propagates the token to the underlying cache, we use a
    // CancellationCheckingDistributedCache that calls ct.ThrowIfCancellationRequested() before
    // delegating, matching what a real distributed cache (e.g. Redis) would do.

    [Fact]
    public async Task StoreAsync_respects_pre_cancelled_CancellationToken()
    {
        var store = CreateStore(cache: new CancellationCheckingDistributedCache());
        using var cts = new CancellationTokenSource();
        cts.Cancel();

        var act = async () =>
            await store.StoreAsync("handle", BuildEntry(), cts.Token);

        await act.Should().ThrowAsync<OperationCanceledException>(
            because: "StoreAsync must honour a pre-cancelled CancellationToken");
    }

    [Fact]
    public async Task FindAsync_respects_pre_cancelled_CancellationToken()
    {
        var store = CreateStore(cache: new CancellationCheckingDistributedCache());
        using var cts = new CancellationTokenSource();
        cts.Cancel();

        var act = async () =>
            await store.FindAsync("handle", cts.Token);

        await act.Should().ThrowAsync<OperationCanceledException>(
            because: "FindAsync must honour a pre-cancelled CancellationToken");
    }

    [Fact]
    public async Task RevokeFamilyAsync_respects_pre_cancelled_CancellationToken()
    {
        var store = CreateStore(cache: new CancellationCheckingDistributedCache());
        using var cts = new CancellationTokenSource();
        cts.Cancel();

        var act = async () =>
            await store.RevokeFamilyAsync("some-family", cts.Token);

        await act.Should().ThrowAsync<OperationCanceledException>(
            because: "RevokeFamilyAsync must honour a pre-cancelled CancellationToken");
    }

    // ── Additional correctness tests ──────────────────────────────────────────────────────────────

    [Fact]
    public async Task FindAsync_returns_null_for_unknown_handle()
    {
        var store = CreateStore();

        var result = await store.FindAsync("never-stored-handle", CancellationToken.None);

        result.Should().BeNull(because: "a handle that was never stored must return null");
    }

    [Fact]
    public async Task TryConsumeAsync_returns_NotFound_for_unknown_handle()
    {
        var store = CreateStore();

        var outcome = await store.TryConsumeAsync("never-stored", "client-a", CancellationToken.None);

        outcome.Should().BeOfType<RefreshTokenConsumptionOutcome.NotFound>(
            because: "a handle that was never stored must return NotFound");
    }

    [Fact]
    public async Task RevokeFamilyAsync_only_affects_tokens_in_that_family()
    {
        var store = CreateStore();
        const string handle1 = "handle-fam-a";
        const string handle2 = "handle-fam-b";

        await store.StoreAsync(handle1, BuildEntry(familyId: "family-a"), CancellationToken.None);
        await store.StoreAsync(handle2, BuildEntry(familyId: "family-b"), CancellationToken.None);

        await store.RevokeFamilyAsync("family-a", CancellationToken.None);

        var resultFamA = await store.FindAsync(handle1, CancellationToken.None);
        var resultFamB = await store.FindAsync(handle2, CancellationToken.None);

        resultFamA.Should().BeNull(because: "family-a has been revoked");
        resultFamB.Should().NotBeNull(because: "family-b has not been revoked");
    }

    [Fact]
    public async Task FindAsync_multiple_calls_do_not_consume_token_and_TryConsumeAsync_still_succeeds()
    {
        var store = CreateStore();
        const string handle = "find-is-non-consuming";

        await store.StoreAsync(handle, BuildEntry(), CancellationToken.None);

        var find1 = await store.FindAsync(handle, CancellationToken.None);
        var find2 = await store.FindAsync(handle, CancellationToken.None);
        var find3 = await store.FindAsync(handle, CancellationToken.None);

        find1.Should().NotBeNull(because: "first FindAsync must return the entry");
        find2.Should().NotBeNull(because: "second FindAsync must return the entry — it is non-consuming");
        find3.Should().NotBeNull(because: "third FindAsync must return the entry — it is non-consuming");

        var outcome = await store.TryConsumeAsync(handle, "client-a", CancellationToken.None);
        outcome.Should().BeOfType<RefreshTokenConsumptionOutcome.Consumed>(
            because: "TryConsumeAsync must succeed after multiple FindAsync calls");
    }

    // ── Tombstone TTL ─────────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task TryConsumeAsync_consumed_tombstone_TTL_equals_RefreshTokenLifetime()
    {
        // Arrange: a token that is about to expire so that the remaining lifetime is very short.
        // The tombstone must be pinned to _refreshTokenLifetime, not to the remaining lifetime,
        // so that reuse-detection survives even when a token is consumed right at its expiry boundary.
        var refreshTokenLifetime = TimeSpan.FromHours(8);
        var serverOptions = new AuthorizationServerOptions();
        serverOptions.TokenEndpoint.RefreshTokenLifetime = refreshTokenLifetime;

        var startTime = new DateTimeOffset(2090, 1, 1, 12, 0, 0, TimeSpan.Zero);
        // Entry expires in 5 seconds — remaining TTL is negligible.
        var expiresAt = startTime.AddSeconds(5);

        var tp = new FakeTimeProvider(startTime);
        var capturingCache = new CapturingDistributedCache(CreateMemoryDistributedCache());
        var store = CreateStore(cache: capturingCache, serverOptions: serverOptions, timeProvider: tp);

        const string handle = "tombstone-ttl-check";
        var entry = BuildEntry(issuedAt: startTime, expiresAt: expiresAt);

        await store.StoreAsync(handle, entry, CancellationToken.None);

        // Act: advance time so only 1 second of entry lifetime remains, then consume.
        tp.Advance(TimeSpan.FromSeconds(4));
        var outcome = await store.TryConsumeAsync(handle, "client-a", CancellationToken.None);

        // Assert: consumed successfully, and tombstone TTL equals _refreshTokenLifetime, not ~1 s.
        outcome.Should().BeOfType<RefreshTokenConsumptionOutcome.Consumed>(
            because: "the token is still valid at the time of consumption");

        var cacheKey = BuildExpectedCacheKey(handle);
        capturingCache.CapturedTtls.Should().ContainKey(cacheKey,
            because: "the tombstone must be written with an explicit TTL");

        // The key is written twice: once for StoreAsync (entry) and once for TryConsumeAsync (tombstone).
        // CapturingDistributedCache retains the last write, which is the tombstone.
        capturingCache.CapturedTtls[cacheKey].Should().Be(refreshTokenLifetime,
            because: "the consumed tombstone TTL must equal _refreshTokenLifetime regardless of " +
                     "how much of the original entry's lifetime remains, so the replay-detection " +
                     "signal is never silently lost when a token is consumed near expiry");
    }

    [Fact]
    public async Task StoreAsync_value_in_cache_is_not_plain_json()
    {
        var capturingCache = new CapturingDistributedCache(CreateMemoryDistributedCache());
        var store = CreateStore(cache: capturingCache);
        const string handle = "handle-for-encryption-check";

        await store.StoreAsync(handle, BuildEntry(), CancellationToken.None);

        var cacheKey = BuildExpectedCacheKey(handle);
        capturingCache.WrittenValues.Should().ContainKey(cacheKey);

        var rawBytes = capturingCache.WrittenValues[cacheKey];
        RefreshTokenEntry? deserialized = null;
        try
        {
            var asText = Encoding.UTF8.GetString(rawBytes);
            deserialized = System.Text.Json.JsonSerializer.Deserialize<RefreshTokenEntry>(
                asText, new System.Text.Json.JsonSerializerOptions(System.Text.Json.JsonSerializerDefaults.Web));
        }
        catch
        {
            // Expected — ciphertext is not valid JSON
        }

        deserialized.Should().BeNull(
            because: "stored bytes must be encrypted ciphertext, not plain JSON");
    }

    [Fact]
    public async Task StoreAsync_writes_entry_under_hashed_key_not_raw_handle()
    {
        var capturingCache = new CapturingDistributedCache(CreateMemoryDistributedCache());
        var store = CreateStore(cache: capturingCache);
        const string handle = "raw-handle-12345";

        await store.StoreAsync(handle, BuildEntry(), CancellationToken.None);

        var expectedKey = BuildExpectedCacheKey(handle);
        capturingCache.WrittenKeys.Should().Contain(expectedKey,
            because: "entry must be stored under the hashed key zkd:rt:{hash}");
        capturingCache.WrittenKeys.Should().NotContain(handle,
            because: "the raw token handle must never be used as a cache key");
    }

    [Fact]
    public async Task RevokeFamilyAsync_writes_plaintext_sentinel_not_encrypted_value()
    {
        // Revocation markers are intentionally NOT DP-encrypted (fail-safe design):
        // a DP failure on a marker would fail open into "not revoked".
        // The sentinel is a single byte [1], not a DP ciphertext.
        var capturingCache = new CapturingDistributedCache(CreateMemoryDistributedCache());
        var store = CreateStore(cache: capturingCache);
        const string familyId = "family-for-sentinel-check";

        await store.RevokeFamilyAsync(familyId, CancellationToken.None);

        var markerKey = BuildExpectedRevocationMarkerKey(familyId);
        capturingCache.WrittenValues.Should().ContainKey(markerKey,
            because: "revocation marker must be written to the cache");

        var markerBytes = capturingCache.WrittenValues[markerKey];
        markerBytes.Should().Equal([1],
            because: "revocation marker must be a plaintext sentinel byte [1], not a DP ciphertext");
    }

    [Fact]
    public async Task RevokeFamilyAsync_marker_TTL_equals_RefreshTokenLifetime_plus_5_minutes()
    {
        var capturingCache = new CapturingDistributedCache(CreateMemoryDistributedCache());
        var refreshTokenLifetime = TimeSpan.FromDays(30);
        var serverOptions = new AuthorizationServerOptions();
        serverOptions.TokenEndpoint.RefreshTokenLifetime = refreshTokenLifetime;

        var store = CreateStore(cache: capturingCache, serverOptions: serverOptions);
        const string familyId = "family-for-marker-ttl-check";

        await store.RevokeFamilyAsync(familyId, CancellationToken.None);

        var markerKey = BuildExpectedRevocationMarkerKey(familyId);
        capturingCache.CapturedTtls.Should().ContainKey(markerKey,
            because: "revocation marker must be written with a TTL");
        var expectedTtl = refreshTokenLifetime + TimeSpan.FromMinutes(5);
        capturingCache.CapturedTtls[markerKey].Should().Be(expectedTtl,
            because: "family revocation markers are always retained for RefreshTokenLifetime + 5 minutes " +
                     "to ensure they outlive all tokens in the family by a small grace margin");
    }

    [Fact]
    public async Task StoreAsync_and_TryConsumeAsync_preserves_PreviousTokenHandleHash()
    {
        var store = CreateStore();
        const string handle = "round-trip-prev-hash";
        var entry = BuildEntry(previousTokenHandleHash: "hash-of-previous-handle");

        await store.StoreAsync(handle, entry, CancellationToken.None);
        var outcome = await store.TryConsumeAsync(handle, "client-a", CancellationToken.None);

        outcome.Should().BeOfType<RefreshTokenConsumptionOutcome.Consumed>()
            .Which.Entry.PreviousTokenHandleHash.Should().Be("hash-of-previous-handle",
            because: "PreviousTokenHandleHash must survive the DP encrypt/decrypt round-trip");
    }

    [Fact]
    public async Task StoreAsync_and_TryConsumeAsync_preserves_null_PreviousTokenHandleHash()
    {
        var store = CreateStore();
        const string handle = "round-trip-null-prev-hash";
        var entry = BuildEntry(previousTokenHandleHash: null);

        await store.StoreAsync(handle, entry, CancellationToken.None);
        var outcome = await store.TryConsumeAsync(handle, "client-a", CancellationToken.None);

        outcome.Should().BeOfType<RefreshTokenConsumptionOutcome.Consumed>()
            .Which.Entry.PreviousTokenHandleHash.Should().BeNull(
            because: "null PreviousTokenHandleHash must survive the round-trip");
    }

    [Fact]
    public async Task StoreAsync_and_FindAsync_preserves_all_entry_fields()
    {
        var store = CreateStore();
        const string handle = "find-round-trip-all-fields";
        var now = new DateTimeOffset(2090, 6, 15, 10, 30, 0, TimeSpan.Zero);
        var entry = new RefreshTokenEntry
        {
            FamilyId = "fam-all-fields",
            ClientId = "client-full",
            Sub = "subject-xyz",
            Scope = ["openid", "profile", "email"],
            SsoSessionId = "sso-session-abc",
            IssuedAt = now,
            ExpiresAt = now.AddHours(8),
            PreviousTokenHandleHash = "abc-def-123",
        };

        await store.StoreAsync(handle, entry, CancellationToken.None);
        var result = await store.FindAsync(handle, CancellationToken.None);

        result.Should().NotBeNull();
        result!.FamilyId.Should().Be(entry.FamilyId);
        result.ClientId.Should().Be(entry.ClientId);
        result.Sub.Should().Be(entry.Sub);
        result.Scope.Should().BeEquivalentTo(entry.Scope);
        result.SsoSessionId.Should().Be(entry.SsoSessionId);
        result.IssuedAt.Should().Be(entry.IssuedAt);
        result.ExpiresAt.Should().Be(entry.ExpiresAt);
        result.PreviousTokenHandleHash.Should().Be(entry.PreviousTokenHandleHash);
    }

    // ── Security: outcome precedence in TryConsumeAsync ──────────────────────────────────────────

    [Fact]
    public async Task TryConsumeAsync_returns_Revoked_not_ClientMismatch_when_family_is_revoked_and_client_mismatches()
    {
        // Revocation check comes before client-mismatch check in the implementation.
        var store = CreateStore();
        const string handle = "revoked-and-wrong-client";
        const string familyId = "fam-revoked-mismatch";

        await store.StoreAsync(handle, BuildEntry(clientId: "client-a", familyId: familyId), CancellationToken.None);
        await store.RevokeFamilyAsync(familyId, CancellationToken.None);

        var outcome = await store.TryConsumeAsync(handle, "client-b", CancellationToken.None);

        outcome.Should().BeOfType<RefreshTokenConsumptionOutcome.Revoked>(
            because: "the revocation check happens before the client-mismatch check");
    }

    [Fact]
    public async Task TryConsumeAsync_returns_AlreadyConsumed_not_Revoked_when_consumed_then_family_revoked_then_replayed()
    {
        // The IsConsumed check (AlreadyConsumed) fires before the revocation check (Revoked)
        // in the implementation.
        var store = CreateStore();
        const string handle = "replay-after-revoke-after-consume";
        const string familyId = "fam-precedence-test";

        await store.StoreAsync(handle, BuildEntry(clientId: "client-a", familyId: familyId), CancellationToken.None);

        var consumeOutcome = await store.TryConsumeAsync(handle, "client-a", CancellationToken.None);
        consumeOutcome.Should().BeOfType<RefreshTokenConsumptionOutcome.Consumed>(
            because: "first consumption must succeed");

        await store.RevokeFamilyAsync(familyId, CancellationToken.None);

        var replayOutcome = await store.TryConsumeAsync(handle, "client-a", CancellationToken.None);

        replayOutcome.Should().BeOfType<RefreshTokenConsumptionOutcome.AlreadyConsumed>(
            because: "the IsConsumed check precedes the revocation check, so a replay against " +
                     "a tombstone in a revoked family must return AlreadyConsumed, not Revoked");
    }

    // ── Helpers ───────────────────────────────────────────────────────────────────────────────────

    /// <summary>
    /// A delegating <see cref="IDistributedCache"/> wrapper that can be configured to throw
    /// an <see cref="InvalidOperationException"/> on specific cache operations in order to
    /// simulate IO failures.
    /// </summary>
    private sealed class FaultingDistributedCache : IDistributedCache
    {
        private readonly IDistributedCache _inner;
        private readonly bool _throwOnSet;
        private readonly bool _throwOnGet;
        private readonly bool _throwOnRemove;
        private readonly int? _throwOnGetAfterNthCall;
        private int _getCallCount;

        public FaultingDistributedCache(
            IDistributedCache inner,
            bool throwOnSet = false,
            bool throwOnGet = false,
            bool throwOnRemove = false,
            int? throwOnGetAfterNthCall = null)
        {
            _inner = inner;
            _throwOnSet = throwOnSet;
            _throwOnGet = throwOnGet;
            _throwOnRemove = throwOnRemove;
            _throwOnGetAfterNthCall = throwOnGetAfterNthCall;
        }

        public byte[]? Get(string key)
        {
            ThrowIfGetShouldFault();
            return _inner.Get(key);
        }

        public Task<byte[]?> GetAsync(string key, CancellationToken token = default)
        {
            ThrowIfGetShouldFault();
            return _inner.GetAsync(key, token);
        }

        public void Set(string key, byte[] value, DistributedCacheEntryOptions options)
        {
            if (_throwOnSet)
                throw new InvalidOperationException("Simulated distributed cache Set failure.");
            _inner.Set(key, value, options);
        }

        public Task SetAsync(string key, byte[] value, DistributedCacheEntryOptions options, CancellationToken token = default)
        {
            if (_throwOnSet)
                throw new InvalidOperationException("Simulated distributed cache Set failure.");
            return _inner.SetAsync(key, value, options, token);
        }

        public void Refresh(string key) => _inner.Refresh(key);
        public Task RefreshAsync(string key, CancellationToken token = default) => _inner.RefreshAsync(key, token);

        public void Remove(string key)
        {
            if (_throwOnRemove)
                throw new InvalidOperationException("Simulated distributed cache Remove failure.");
            _inner.Remove(key);
        }

        public Task RemoveAsync(string key, CancellationToken token = default)
        {
            if (_throwOnRemove)
                throw new InvalidOperationException("Simulated distributed cache Remove failure.");
            return _inner.RemoveAsync(key, token);
        }

        private void ThrowIfGetShouldFault()
        {
            _getCallCount++;
            if (_throwOnGet)
                throw new InvalidOperationException("Simulated distributed cache Get failure.");
            if (_throwOnGetAfterNthCall.HasValue && _getCallCount >= _throwOnGetAfterNthCall.Value)
                throw new InvalidOperationException("Simulated distributed cache Get failure (nth call).");
        }
    }

    /// <summary>
    /// A delegating <see cref="IDistributedCache"/> wrapper that records the keys, values,
    /// and TTL options used in every <see cref="SetAsync"/> call.
    /// </summary>
    private sealed class CapturingDistributedCache : IDistributedCache
    {
        private readonly IDistributedCache _inner;

        public HashSet<string> WrittenKeys { get; } = new();
        public Dictionary<string, byte[]> WrittenValues { get; } = new();
        public Dictionary<string, TimeSpan> CapturedTtls { get; } = new();

        public CapturingDistributedCache(IDistributedCache inner) => _inner = inner;

        public byte[]? Get(string key) => _inner.Get(key);
        public Task<byte[]?> GetAsync(string key, CancellationToken token = default) => _inner.GetAsync(key, token);

        public void Set(string key, byte[] value, DistributedCacheEntryOptions options)
        {
            RecordWrite(key, value, options);
            _inner.Set(key, value, options);
        }

        public Task SetAsync(string key, byte[] value, DistributedCacheEntryOptions options, CancellationToken token = default)
        {
            RecordWrite(key, value, options);
            return _inner.SetAsync(key, value, options, token);
        }

        public void Refresh(string key) => _inner.Refresh(key);
        public Task RefreshAsync(string key, CancellationToken token = default) => _inner.RefreshAsync(key, token);
        public void Remove(string key) => _inner.Remove(key);
        public Task RemoveAsync(string key, CancellationToken token = default) => _inner.RemoveAsync(key, token);

        private void RecordWrite(string key, byte[] value, DistributedCacheEntryOptions options)
        {
            WrittenKeys.Add(key);
            WrittenValues[key] = value;
            if (options.AbsoluteExpirationRelativeToNow.HasValue)
                CapturedTtls[key] = options.AbsoluteExpirationRelativeToNow.Value;
        }
    }

    /// <summary>
    /// A minimal <see cref="IDistributedCache"/> implementation that calls
    /// <see cref="CancellationToken.ThrowIfCancellationRequested"/> on every async operation.
    /// This is used to verify that stores propagate the CancellationToken to the cache,
    /// since <see cref="MemoryDistributedCache"/> does not honour pre-cancelled tokens.
    /// </summary>
    private sealed class CancellationCheckingDistributedCache : IDistributedCache
    {
        public byte[]? Get(string key) => null;

        public Task<byte[]?> GetAsync(string key, CancellationToken token = default)
        {
            token.ThrowIfCancellationRequested();
            return Task.FromResult<byte[]?>(null);
        }

        public void Set(string key, byte[] value, DistributedCacheEntryOptions options) { }

        public Task SetAsync(string key, byte[] value, DistributedCacheEntryOptions options, CancellationToken token = default)
        {
            token.ThrowIfCancellationRequested();
            return Task.CompletedTask;
        }

        public void Refresh(string key) { }
        public Task RefreshAsync(string key, CancellationToken token = default)
        {
            token.ThrowIfCancellationRequested();
            return Task.CompletedTask;
        }

        public void Remove(string key) { }
        public Task RemoveAsync(string key, CancellationToken token = default)
        {
            token.ThrowIfCancellationRequested();
            return Task.CompletedTask;
        }
    }
}
