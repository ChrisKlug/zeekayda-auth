using System.Buffers.Text;
using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Time.Testing;
using ZeeKayDa.Auth.Authorization;
using ZeeKayDa.Auth.Stores;

namespace ZeeKayDa.Auth.Tests.Stores;

/// <summary>
/// Tests for <see cref="DistributedCacheAuthorizationCodeStore"/> covering all acceptance criteria.
/// </summary>
/// <remarks>
/// Uses <see cref="MemoryDistributedCache"/> as the backing store so tests are self-contained
/// and fast. To simulate IO failures, a <see cref="FaultingDistributedCache"/> delegate wrapper
/// is used that can be configured to throw on specific operations.
/// </remarks>
public sealed class DistributedCacheAuthorizationCodeStoreTests
{
    /// <summary>
    /// A far-future date used as ExpiresAt so entries are never evicted by the real clock.
    /// </summary>
    private static readonly DateTimeOffset FarFuture = new(2099, 1, 1, 0, 0, 0, TimeSpan.Zero);

    // ── Factory helpers ───────────────────────────────────────────────────────────────────────────

    private static DistributedCacheAuthorizationCodeStore CreateStore(
        IDistributedCache? cache = null,
        IDataProtectionProvider? dp = null,
        AuthorizationServerOptions? serverOptions = null,
        TimeProvider? timeProvider = null)
    {
        return new DistributedCacheAuthorizationCodeStore(
            cache ?? CreateMemoryDistributedCache(),
            dp ?? new EphemeralDataProtectionProvider(),
            new OptionsWrapper<AuthorizationServerOptions>(serverOptions ?? new AuthorizationServerOptions()),
            timeProvider ?? TimeProvider.System);
    }

    private static IDistributedCache CreateMemoryDistributedCache()
        => new MemoryDistributedCache(
            new OptionsWrapper<MemoryDistributedCacheOptions>(new MemoryDistributedCacheOptions()));

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

    private static string ComputeExpectedHashedSegment(string handle)
    {
        var inputBytes = Encoding.UTF8.GetBytes(handle);
        var hash = SHA256.HashData(inputBytes);
        return Base64Url.EncodeToString(hash);
    }

    private static string BuildExpectedEntryKey(string handle)
        => $"zkd:code:{ComputeExpectedHashedSegment(handle)}";

    private static string BuildExpectedTombstoneKey(string handle)
        => $"zkd:code:{ComputeExpectedHashedSegment(handle)}:redeemed";

    // ── AC 1 — StoreAsync then TryRedeemAsync with correct client → Redeemed ─────────────────────

    [Fact]
    public async Task StoreAsync_then_TryRedeemAsync_with_correct_client_returns_Redeemed()
    {
        var store = CreateStore();
        const string code = "valid-code-1";
        var entry = BuildEntry(clientId: "client-a");

        await store.StoreAsync(code, entry, CancellationToken.None);
        var outcome = await store.TryRedeemAsync(code, "client-a", "family-1", CancellationToken.None);

        outcome.Should().BeOfType<AuthorizationCodeRedemptionOutcome.Redeemed>(
            because: "a valid, unexpired code presented by the correct client must return Redeemed");
    }

    [Fact]
    public async Task TryRedeemAsync_Redeemed_entry_matches_stored_entry()
    {
        const string code = "round-trip-code";
        var now = new DateTimeOffset(2090, 1, 1, 12, 0, 0, TimeSpan.Zero);
        var entry = BuildEntry(clientId: "client-a", issuedAt: now, expiresAt: now.AddMinutes(5));

        var tp = new FakeTimeProvider(now);
        var storeWithTime = CreateStore(timeProvider: tp);
        await storeWithTime.StoreAsync(code, entry, CancellationToken.None);
        var outcome = await storeWithTime.TryRedeemAsync(code, "client-a", "family-1", CancellationToken.None);

        outcome.Should().BeOfType<AuthorizationCodeRedemptionOutcome.Redeemed>()
            .Which.Entry.Should().BeEquivalentTo(entry,
            because: "the redeemed entry must match the stored entry exactly");
    }

    // ── AC 2 — ClientMismatch does NOT consume the code ──────────────────────────────────────────

    [Fact]
    public async Task TryRedeemAsync_with_wrong_client_returns_ClientMismatch()
    {
        var store = CreateStore();
        const string code = "client-mismatch-code";

        await store.StoreAsync(code, BuildEntry(clientId: "client-a"), CancellationToken.None);
        var outcome = await store.TryRedeemAsync(code, "client-b", "family-wrong", CancellationToken.None);

        outcome.Should().BeOfType<AuthorizationCodeRedemptionOutcome.ClientMismatch>(
            because: "presenting client does not match the bound client");
    }

    [Fact]
    public async Task TryRedeemAsync_ClientMismatch_does_not_consume_code_allowing_legitimate_client_to_redeem()
    {
        var store = CreateStore();
        const string code = "client-mismatch-no-consume";

        await store.StoreAsync(code, BuildEntry(clientId: "client-a"), CancellationToken.None);

        var mismatchOutcome = await store.TryRedeemAsync(code, "client-b", "family-wrong", CancellationToken.None);
        mismatchOutcome.Should().BeOfType<AuthorizationCodeRedemptionOutcome.ClientMismatch>(
            because: "presenting client does not match the bound client");

        var redeemedOutcome = await store.TryRedeemAsync(code, "client-a", "family-correct", CancellationToken.None);
        redeemedOutcome.Should().BeOfType<AuthorizationCodeRedemptionOutcome.Redeemed>(
            because: "ClientMismatch must leave the code intact for the legitimate client");
    }

    // ── AC 3 — AlreadyRedeemed after successful redemption ───────────────────────────────────────

    [Fact]
    public async Task TryRedeemAsync_after_successful_redemption_returns_AlreadyRedeemed()
    {
        var store = CreateStore();
        const string code = "replay-attack-code";

        await store.StoreAsync(code, BuildEntry(), CancellationToken.None);
        await store.TryRedeemAsync(code, "client-a", "family-original", CancellationToken.None);

        var replayOutcome = await store.TryRedeemAsync(code, "client-a", "family-replay", CancellationToken.None);

        replayOutcome.Should().BeOfType<AuthorizationCodeRedemptionOutcome.AlreadyRedeemed>(
            because: "a replayed code must return AlreadyRedeemed after successful redemption");
    }

    [Fact]
    public async Task TryRedeemAsync_AlreadyRedeemed_carries_original_family_id()
    {
        var store = CreateStore();
        const string code = "family-id-check-code";

        await store.StoreAsync(code, BuildEntry(), CancellationToken.None);
        await store.TryRedeemAsync(code, "client-a", "original-family", CancellationToken.None);
        var replayOutcome = await store.TryRedeemAsync(code, "client-a", "new-family", CancellationToken.None);

        replayOutcome.Should().BeOfType<AuthorizationCodeRedemptionOutcome.AlreadyRedeemed>()
            .Which.FamilyId.Should().Be("original-family",
            because: "the tombstone must preserve the original family ID, not the replayed one");
    }

    // ── AC 4 — Unknown code → NotFound ───────────────────────────────────────────────────────────

    [Fact]
    public async Task TryRedeemAsync_for_unknown_code_returns_NotFound()
    {
        var store = CreateStore();

        var outcome = await store.TryRedeemAsync("never-stored-code", "client-a", "family-1", CancellationToken.None);

        outcome.Should().BeOfType<AuthorizationCodeRedemptionOutcome.NotFound>(
            because: "a code that was never stored must return NotFound");
    }

    // ── AC 5 — Expired entry → NotFound ──────────────────────────────────────────────────────────

    [Fact]
    public async Task TryRedeemAsync_for_expired_entry_returns_NotFound()
    {
        var startTime = new DateTimeOffset(2090, 1, 1, 12, 0, 0, TimeSpan.Zero);
        var expiresAt = startTime.AddMinutes(1);

        var tp = new FakeTimeProvider(startTime);
        var store = CreateStore(timeProvider: tp);
        const string code = "expiry-check-code";
        var entry = BuildEntry(issuedAt: startTime, expiresAt: expiresAt);

        await store.StoreAsync(code, entry, CancellationToken.None);

        // Advance FakeTimeProvider past ExpiresAt — the distributed cache uses relative TTL
        // from store time and won't evict immediately, so the logical expiry check fires
        tp.Advance(TimeSpan.FromMinutes(2));

        var outcome = await store.TryRedeemAsync(code, "client-a", "family-1", CancellationToken.None);

        outcome.Should().BeOfType<AuthorizationCodeRedemptionOutcome.NotFound>(
            because: "the store must use TimeProvider.GetUtcNow() to check logical expiry");
    }

    // ── AC 6 — Tombstone decryption failure → AlreadyRedeemed { FamilyId = "" } ─────────────────

    [Fact]
    public async Task TryRedeemAsync_returns_AlreadyRedeemed_with_empty_FamilyId_when_tombstone_is_unreadable()
    {
        // Simulate DP key rotation: store1 writes the entry and creates the tombstone.
        // store2 uses a different key ring and cannot decrypt the tombstone.
        var sharedCache = CreateMemoryDistributedCache();
        var dp1 = new EphemeralDataProtectionProvider();
        var dp2 = new EphemeralDataProtectionProvider();

        var store1 = CreateStore(cache: sharedCache, dp: dp1);
        var store2 = CreateStore(cache: sharedCache, dp: dp2);
        const string code = "dp-rotation-replay-code";

        await store1.StoreAsync(code, BuildEntry(), CancellationToken.None);
        var firstOutcome = await store1.TryRedeemAsync(code, "client-a", "family-original", CancellationToken.None);
        firstOutcome.Should().BeOfType<AuthorizationCodeRedemptionOutcome.Redeemed>(
            because: "first redemption via store1 must succeed");

        // Tombstone exists encrypted under dp1. Store2 uses dp2 — Unprotect throws CryptographicException.
        var outcome = await store2.TryRedeemAsync(code, "client-a", "family-replay", CancellationToken.None);

        outcome.Should().BeOfType<AuthorizationCodeRedemptionOutcome.AlreadyRedeemed>(
            because: "a tombstone that cannot be unprotected must still return AlreadyRedeemed");
        outcome.As<AuthorizationCodeRedemptionOutcome.AlreadyRedeemed>().FamilyId.Should().Be(string.Empty,
            because: "when the tombstone ciphertext is unreadable the FamilyId must be empty");
    }

    // ── AC 7 — Entry decryption failure → NotFound ───────────────────────────────────────────────

    [Fact]
    public async Task TryRedeemAsync_returns_NotFound_when_entry_is_unreadable()
    {
        // Simulate DP key rotation: store1 writes the entry with dp1. store2 uses dp2 and cannot decrypt.
        var sharedCache = CreateMemoryDistributedCache();
        var dp1 = new EphemeralDataProtectionProvider();
        var dp2 = new EphemeralDataProtectionProvider();

        var store1 = CreateStore(cache: sharedCache, dp: dp1);
        var store2 = CreateStore(cache: sharedCache, dp: dp2);
        const string code = "dp-rotation-entry-unreadable";

        await store1.StoreAsync(code, BuildEntry(), CancellationToken.None);

        // No tombstone exists — the entry bytes cannot be decrypted under dp2.
        var outcome = await store2.TryRedeemAsync(code, "client-a", "family-1", CancellationToken.None);

        outcome.Should().BeOfType<AuthorizationCodeRedemptionOutcome.NotFound>(
            because: "an entry that cannot be unprotected (DP key rotation) must return NotFound, " +
                     "not AlreadyRedeemed — no tombstone exists so this is not a detected replay");
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
            await store.StoreAsync("expired-code", entry, CancellationToken.None);

        await act.Should().ThrowAsync<ZeeKayDaStoreException>(
            because: "storing an already-expired entry must be rejected to prevent silent TTL clamping");
    }

    // ── AC 8 — StoreAsync with IO failure → ZeeKayDaStoreException ───────────────────────────────

    [Fact]
    public async Task StoreAsync_wraps_distributed_cache_exception_in_ZeeKayDaStoreException()
    {
        var faultingCache = new FaultingDistributedCache(
            CreateMemoryDistributedCache(),
            throwOnSet: true);
        var store = CreateStore(cache: faultingCache);

        var act = async () =>
            await store.StoreAsync("any-code", BuildEntry(), CancellationToken.None);

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
            () => store.StoreAsync("code", BuildEntry(), CancellationToken.None));

        exception.Message.Should().NotBeNullOrWhiteSpace(
            because: "ZeeKayDaStoreException must carry a descriptive message");
    }

    // ── AC 9 — TryRedeemAsync tombstone-read IO failure → ZeeKayDaStoreException ─────────────────

    [Fact]
    public async Task TryRedeemAsync_wraps_tombstone_read_IO_failure_in_ZeeKayDaStoreException()
    {
        var innerCache = CreateMemoryDistributedCache();

        // Write the entry successfully first
        var writeStore = CreateStore(cache: innerCache);
        await writeStore.StoreAsync("code-tombstone-read-fail", BuildEntry(), CancellationToken.None);

        // Now use a faulting cache that throws on Get (tombstone read is the first Get call)
        var faultingCache = new FaultingDistributedCache(innerCache, throwOnGet: true);
        var store = CreateStore(cache: faultingCache);

        var act = async () =>
            await store.TryRedeemAsync("code-tombstone-read-fail", "client-a", "family-1", CancellationToken.None);

        await act.Should().ThrowAsync<ZeeKayDaStoreException>(
            because: "IO failure reading the tombstone must be wrapped in ZeeKayDaStoreException");
    }

    // ── AC 10 — TryRedeemAsync entry-read IO failure → ZeeKayDaStoreException ───────────────────

    [Fact]
    public async Task TryRedeemAsync_wraps_entry_read_IO_failure_in_ZeeKayDaStoreException()
    {
        var innerCache = CreateMemoryDistributedCache();

        // Write the entry successfully
        var writeStore = CreateStore(cache: innerCache);
        await writeStore.StoreAsync("code-entry-read-fail", BuildEntry(), CancellationToken.None);

        // Throw only on the second Get call (first=tombstone read which returns null, second=entry read)
        var faultingCache = new FaultingDistributedCache(innerCache, throwOnGetAfterNthCall: 2);
        var store = CreateStore(cache: faultingCache);

        var act = async () =>
            await store.TryRedeemAsync("code-entry-read-fail", "client-a", "family-1", CancellationToken.None);

        await act.Should().ThrowAsync<ZeeKayDaStoreException>(
            because: "IO failure reading the entry (second Get) must be wrapped in ZeeKayDaStoreException");
    }

    // ── AC 11 — TryRedeemAsync tombstone-write IO failure → ZeeKayDaStoreException ───────────────

    [Fact]
    public async Task TryRedeemAsync_wraps_tombstone_write_IO_failure_in_ZeeKayDaStoreException()
    {
        var innerCache = CreateMemoryDistributedCache();

        // Share the same DP provider so the reading store can decrypt what the writing store stored
        var sharedDp = new EphemeralDataProtectionProvider();

        var writeStore = CreateStore(cache: innerCache, dp: sharedDp);
        await writeStore.StoreAsync("code-tombstone-write-fail", BuildEntry(), CancellationToken.None);

        // Throw only on Set (tombstone write) — Gets succeed so we reach the tombstone write step
        var faultingCache = new FaultingDistributedCache(innerCache, throwOnSet: true);
        var store = CreateStore(cache: faultingCache, dp: sharedDp);

        var act = async () =>
            await store.TryRedeemAsync("code-tombstone-write-fail", "client-a", "family-1", CancellationToken.None);

        await act.Should().ThrowAsync<ZeeKayDaStoreException>(
            because: "IO failure writing the tombstone must be wrapped in ZeeKayDaStoreException");
    }

    // ── AC 12 — TryRedeemAsync entry-removal IO failure → ZeeKayDaStoreException ─────────────────

    [Fact]
    public async Task TryRedeemAsync_wraps_entry_removal_IO_failure_in_ZeeKayDaStoreException()
    {
        var innerCache = CreateMemoryDistributedCache();

        // Share the same DP provider so the reading store can decrypt what the writing store stored
        var sharedDp = new EphemeralDataProtectionProvider();

        var writeStore = CreateStore(cache: innerCache, dp: sharedDp);
        await writeStore.StoreAsync("code-removal-fail", BuildEntry(), CancellationToken.None);

        // Throw only on Remove (entry deletion step after tombstone is written)
        var faultingCache = new FaultingDistributedCache(innerCache, throwOnRemove: true);
        var store = CreateStore(cache: faultingCache, dp: sharedDp);

        var act = async () =>
            await store.TryRedeemAsync("code-removal-fail", "client-a", "family-1", CancellationToken.None);

        await act.Should().ThrowAsync<ZeeKayDaStoreException>(
            because: "IO failure removing the entry must be wrapped in ZeeKayDaStoreException");
    }

    // ── AC 13 — Tombstone TTL always equals RefreshTokenLifetime ─────────────────────────────────

    [Fact]
    public async Task Tombstone_TTL_equals_RefreshTokenLifetime()
    {
        var startTime = new DateTimeOffset(2090, 1, 1, 12, 0, 0, TimeSpan.Zero);
        var tp = new FakeTimeProvider(startTime);
        var capturingCache = new CapturingDistributedCache(CreateMemoryDistributedCache());

        var refreshTokenLifetime = TimeSpan.FromDays(14);
        var serverOptions = new AuthorizationServerOptions();
        serverOptions.TokenEndpoint.RefreshTokenLifetime = refreshTokenLifetime;

        var store = CreateStore(
            cache: capturingCache,
            serverOptions: serverOptions,
            timeProvider: tp);

        const string code = "tombstone-ttl-check";
        await store.StoreAsync(code, BuildEntry(expiresAt: startTime.AddMinutes(5)), CancellationToken.None);
        await store.TryRedeemAsync(code, "client-a", "family-1", CancellationToken.None);

        var tombstoneKey = BuildExpectedTombstoneKey(code);
        capturingCache.CapturedTtls.Should().ContainKey(tombstoneKey,
            because: "tombstone must have been written to the cache");
        capturingCache.CapturedTtls[tombstoneKey].Should().BeCloseTo(refreshTokenLifetime, precision: TimeSpan.FromSeconds(1),
            because: "tombstone TTL must always equal RefreshTokenLifetime");
    }

    // ── AC 14 — Null argument guards ─────────────────────────────────────────────────────────────

    [Fact]
    public void Constructor_throws_ArgumentNullException_for_null_cache()
    {
        var act = () => new DistributedCacheAuthorizationCodeStore(
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
        var act = () => new DistributedCacheAuthorizationCodeStore(
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
        var act = () => new DistributedCacheAuthorizationCodeStore(
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
        var act = () => new DistributedCacheAuthorizationCodeStore(
            CreateMemoryDistributedCache(),
            new EphemeralDataProtectionProvider(),
            new OptionsWrapper<AuthorizationServerOptions>(new AuthorizationServerOptions()),
            null!);

        act.Should().Throw<ArgumentNullException>(
            because: "null TimeProvider must be rejected at construction time");
    }

    [Fact]
    public async Task StoreAsync_throws_ArgumentNullException_for_null_code()
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
            await store.StoreAsync("code", null!, CancellationToken.None);

        await act.Should().ThrowAsync<ArgumentNullException>();
    }

    [Fact]
    public async Task TryRedeemAsync_throws_ArgumentNullException_for_null_code()
    {
        var store = CreateStore();

        var act = async () =>
            await store.TryRedeemAsync(null!, "client-a", "family-1", CancellationToken.None);

        await act.Should().ThrowAsync<ArgumentNullException>();
    }

    [Fact]
    public async Task TryRedeemAsync_throws_ArgumentNullException_for_null_clientId()
    {
        var store = CreateStore();

        var act = async () =>
            await store.TryRedeemAsync("code", null!, "family-1", CancellationToken.None);

        await act.Should().ThrowAsync<ArgumentNullException>();
    }

    [Fact]
    public async Task TryRedeemAsync_throws_ArgumentNullException_for_null_familyId()
    {
        var store = CreateStore();

        var act = async () =>
            await store.TryRedeemAsync("code", "client-a", null!, CancellationToken.None);

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
            await store.StoreAsync("code", BuildEntry(), cts.Token);

        await act.Should().ThrowAsync<OperationCanceledException>(
            because: "StoreAsync must honour a pre-cancelled CancellationToken");
    }

    [Fact]
    public async Task TryRedeemAsync_respects_pre_cancelled_CancellationToken()
    {
        var store = CreateStore(cache: new CancellationCheckingDistributedCache());
        using var cts = new CancellationTokenSource();
        cts.Cancel();

        var act = async () =>
            await store.TryRedeemAsync("code", "client-a", "family-1", cts.Token);

        await act.Should().ThrowAsync<OperationCanceledException>(
            because: "TryRedeemAsync must honour a pre-cancelled CancellationToken");
    }

    // ── Key format — raw handle must not appear as a cache key ───────────────────────────────────

    [Fact]
    public async Task StoreAsync_writes_entry_under_hashed_key_not_raw_handle()
    {
        var capturingCache = new CapturingDistributedCache(CreateMemoryDistributedCache());
        var store = CreateStore(cache: capturingCache);
        const string code = "raw-handle-12345";

        await store.StoreAsync(code, BuildEntry(), CancellationToken.None);

        var expectedKey = BuildExpectedEntryKey(code);
        capturingCache.WrittenKeys.Should().Contain(expectedKey,
            because: "entry must be stored under the hashed key zkd:code:{hash}");
        capturingCache.WrittenKeys.Should().NotContain(code,
            because: "the raw code handle must never be used as a cache key");
    }

    [Fact]
    public async Task StoreAsync_value_in_cache_is_not_plain_json()
    {
        // Verify the stored bytes are encrypted ciphertext, not raw JSON
        var capturingCache = new CapturingDistributedCache(CreateMemoryDistributedCache());
        var store = CreateStore(cache: capturingCache);
        const string code = "code-for-encryption-check";

        await store.StoreAsync(code, BuildEntry(), CancellationToken.None);

        var entryKey = BuildExpectedEntryKey(code);
        capturingCache.WrittenValues.Should().ContainKey(entryKey);

        var rawBytes = capturingCache.WrittenValues[entryKey];
        AuthorizationCodeEntry? deserialized = null;
        try
        {
            var asText = Encoding.UTF8.GetString(rawBytes);
            deserialized = System.Text.Json.JsonSerializer.Deserialize<AuthorizationCodeEntry>(
                asText, new System.Text.Json.JsonSerializerOptions(System.Text.Json.JsonSerializerDefaults.Web));
        }
        catch
        {
            // Expected — ciphertext is not valid JSON
        }

        deserialized.Should().BeNull(
            because: "stored bytes must be encrypted ciphertext, not plain JSON");
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
    /// A delegating <see cref="IDistributedCache"/> wrapper that records the keys and values
    /// written via <see cref="SetAsync"/> and the TTL options used.
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
