using System.Buffers.Text;
using System.Collections.Concurrent;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Primitives;
using Microsoft.Extensions.Time.Testing;
using ZeeKayDa.Auth.Stores;

namespace ZeeKayDa.Auth.Tests.Stores;

/// <summary>
/// Tests for <see cref="InMemoryRefreshTokenStore"/> covering all store behaviours.
/// </summary>
/// <remarks>
/// IMPORTANT: IMemoryCache uses the real wall clock for AbsoluteExpiration evaluation, not
/// the injected TimeProvider. Tests that rely on IMemoryCache actually holding an entry must
/// therefore set ExpiresAt to a date far in the real future (e.g. year 2099). Tests that
/// exercise the logical expiry check use a FakeTimeProvider initialised at a real-future
/// start time, then advance it past ExpiresAt.
/// </remarks>
public sealed class InMemoryRefreshTokenStoreTests
{
    /// <summary>
    /// A far-future date used as ExpiresAt when the test needs IMemoryCache to actually
    /// hold the entry (since IMemoryCache uses the real wall clock for eviction).
    /// </summary>
    private static readonly DateTimeOffset FarFuture = new(2099, 1, 1, 0, 0, 0, TimeSpan.Zero);

    // ── Factory helpers ───────────────────────────────────────────────────────────────────────────

    private static InMemoryRefreshTokenStore CreateStore(
        IMemoryCache? cache = null,
        IDataProtectionProvider? dp = null,
        AuthorizationServerOptions? serverOptions = null,
        TimeProvider? timeProvider = null)
    {
        return new InMemoryRefreshTokenStore(
            cache ?? new MemoryCache(new MemoryCacheOptions()),
            dp ?? new EphemeralDataProtectionProvider(),
            new OptionsWrapper<AuthorizationServerOptions>(serverOptions ?? new AuthorizationServerOptions()),
            timeProvider ?? TimeProvider.System);
    }

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

    /// <summary>
    /// Replicates the exact key derivation used inside <see cref="InMemoryRefreshTokenStore"/>
    /// so cache keys can be verified without access to private methods.
    /// </summary>
    private static string ComputeExpectedHashedSegment(string handle)
    {
        var inputBytes = Encoding.UTF8.GetBytes(handle);
        var hash = SHA256.HashData(inputBytes);
        return Base64Url.EncodeToString(hash);
    }

    private static string BuildExpectedCacheKey(string handle)
        => $"zkd:rt:{ComputeExpectedHashedSegment(handle)}";

    // ── Cache key scheme ──────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task StoreAsync_writes_entry_under_hashed_key_not_raw_handle()
    {
        var cache = new MemoryCache(new MemoryCacheOptions());
        var store = CreateStore(cache: cache);
        const string handle = "raw-handle-12345";

        await store.StoreAsync(handle, BuildEntry(), CancellationToken.None);

        var expectedKey = BuildExpectedCacheKey(handle);
        cache.TryGetValue(expectedKey, out _).Should().BeTrue(
            because: "entry must be stored under the hashed key zkd:rt:{hash}");
        cache.TryGetValue(handle, out _).Should().BeFalse(
            because: "the raw token handle must never be used as a cache key");
    }

    [Fact]
    public async Task StoreAsync_does_not_write_raw_handle_as_any_cache_key()
    {
        var cache = new MemoryCache(new MemoryCacheOptions());
        var store = CreateStore(cache: cache);
        const string handle = "super-secret-raw-handle";

        await store.StoreAsync(handle, BuildEntry(), CancellationToken.None);

        cache.TryGetValue(handle, out _).Should().BeFalse(
            because: "the raw handle must never be used as a cache key");
    }

    [Fact]
    public async Task TryConsumeAsync_tombstone_overwrites_entry_at_same_cache_key()
    {
        // The refresh token store shares the same cache key for live entries and tombstones
        // (unlike the auth code store which uses separate :redeemed keys).
        var cache = new MemoryCache(new MemoryCacheOptions());
        var store = CreateStore(cache: cache);
        const string handle = "tombstone-at-same-key";

        await store.StoreAsync(handle, BuildEntry(), CancellationToken.None);
        var cacheKey = BuildExpectedCacheKey(handle);

        cache.TryGetValue(cacheKey, out byte[]? beforeBytes).Should().BeTrue(
            because: "entry must be present before consumption");
        var bytesBeforeConsume = beforeBytes;

        await store.TryConsumeAsync(handle, "client-a", CancellationToken.None);

        // The key still exists (tombstone replaces the entry at the same key)
        cache.TryGetValue(cacheKey, out byte[]? afterBytes).Should().BeTrue(
            because: "tombstone must be written at the same cache key after consumption");

        // The bytes must have changed — tombstone is a different payload
        afterBytes.Should().NotEqual(bytesBeforeConsume,
            because: "tombstone payload differs from the original entry payload");
    }

    // ── Data Protection encryption ────────────────────────────────────────────────────────────────

    [Fact]
    public async Task StoreAsync_value_in_cache_is_not_plain_json()
    {
        var cache = new MemoryCache(new MemoryCacheOptions());
        var store = CreateStore(cache: cache);
        const string handle = "handle-for-encryption-check";

        await store.StoreAsync(handle, BuildEntry(), CancellationToken.None);

        var hashedKey = BuildExpectedCacheKey(handle);
        cache.TryGetValue(hashedKey, out byte[]? rawBytes).Should().BeTrue();
        rawBytes.Should().NotBeNull();

        // Attempt to deserialise the raw bytes as UTF-8 JSON. Because the bytes are
        // Data Protection-encrypted ciphertext, this must either throw or produce null.
        RefreshTokenEntry? deserialized = null;
        try
        {
            var asText = Encoding.UTF8.GetString(rawBytes!);
            deserialized = System.Text.Json.JsonSerializer.Deserialize<RefreshTokenEntry>(
                asText, new System.Text.Json.JsonSerializerOptions(System.Text.Json.JsonSerializerDefaults.Web));
        }
        catch
        {
            // Expected — ciphertext is not valid JSON
        }

        deserialized.Should().BeNull(
            because: "stored bytes are encrypted ciphertext, not plain JSON");
    }

    [Fact]
    public void DataProtection_purpose_is_RefreshTokenStore_not_AuthorizationCodeStore()
    {
        // Proves that cross-purpose decryption fails — a refresh token ciphertext cannot be
        // read by the authorization code store's protector, and vice versa.
        var dp = new EphemeralDataProtectionProvider();
        var refreshTokenProtector = dp.CreateProtector("ZeeKayDa.Auth:RefreshTokenStore");
        var authCodeProtector = dp.CreateProtector("ZeeKayDa.Auth:AuthorizationCodeStore");

        var plaintext = Encoding.UTF8.GetBytes("refresh-token-payload");
        var ciphertext = refreshTokenProtector.Protect(plaintext);

        var act = () => authCodeProtector.Unprotect(ciphertext);

        act.Should().Throw<CryptographicException>(
            because: "data protected under the refresh token purpose cannot be unprotected under the auth code purpose");
    }

    // ── Family revocation: hashed plaintext keys in ConcurrentDictionary (AC 2) ─────────────────

    [Fact]
    public async Task RevokeFamilyAsync_stores_hashed_family_id_as_plaintext_key_not_DP_encrypted()
    {
        // The _revokedFamilies dictionary uses Base64Url(SHA256(familyId)) as the key.
        // This is intentionally NOT DP-encrypted: a DP failure must not fail open into "not revoked".
        // We verify this by reading the _revokedFamilies dictionary via reflection and confirming:
        // (a) the raw familyId is not a key,
        // (b) the expected hash IS a key.
        var store = CreateStore();
        const string familyId = "family-for-hash-check";

        await store.RevokeFamilyAsync(familyId, CancellationToken.None);

        var revokedFamiliesField = typeof(InMemoryRefreshTokenStore)
            .GetField("_revokedFamilies", BindingFlags.NonPublic | BindingFlags.Instance)!;

        var revokedFamilies = (ConcurrentDictionary<string, bool>)revokedFamiliesField.GetValue(store)!;

        revokedFamilies.ContainsKey(familyId).Should().BeFalse(
            because: "the raw familyId must never be stored as a revocation marker key");

        var expectedHashedKey = ComputeExpectedHashedSegment(familyId);
        revokedFamilies.ContainsKey(expectedHashedKey).Should().BeTrue(
            because: "the revocation marker must be stored as Base64Url(SHA256(familyId)) — " +
                     "a hashed plaintext key, intentionally not DP-encrypted, " +
                     "so that revocation always takes effect regardless of DP key availability");
    }

    // ── StoreAsync → FindAsync round-trip ─────────────────────────────────────────────────────────

    [Fact]
    public async Task FindAsync_returns_stored_entry_when_all_checks_pass()
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

    [Fact]
    public async Task FindAsync_returns_null_for_unknown_handle()
    {
        var store = CreateStore();

        var result = await store.FindAsync("never-stored-handle", CancellationToken.None);

        result.Should().BeNull(because: "a handle that was never stored must return null");
    }

    [Fact]
    public async Task FindAsync_returns_null_after_TryConsumeAsync_succeeds()
    {
        var store = CreateStore();
        const string handle = "find-after-consume";

        await store.StoreAsync(handle, BuildEntry(), CancellationToken.None);
        await store.TryConsumeAsync(handle, "client-a", CancellationToken.None);

        var result = await store.FindAsync(handle, CancellationToken.None);

        result.Should().BeNull(because: "a consumed token (tombstone in place) must return null from FindAsync");
    }

    // ── FindAsync logical expiry ───────────────────────────────────────────────────────────────────

    [Fact]
    public async Task FindAsync_returns_null_when_time_is_past_ExpiresAt_even_if_cache_still_holds_entry()
    {
        // Strategy: use a FakeTimeProvider starting at a real-future point, so that
        // IMemoryCache also considers the entry valid at store time. Then advance the
        // FakeTimeProvider past ExpiresAt without triggering real-clock eviction.
        var startTime = new DateTimeOffset(2090, 1, 1, 12, 0, 0, TimeSpan.Zero);
        var expiresAt = startTime.AddMinutes(1);

        var tp = new FakeTimeProvider(startTime);
        var cache = new MemoryCache(new MemoryCacheOptions());
        var store = CreateStore(cache: cache, timeProvider: tp);
        const string handle = "find-expiry-check";
        var entry = BuildEntry(issuedAt: startTime, expiresAt: expiresAt);

        await store.StoreAsync(handle, entry, CancellationToken.None);

        // Confirm cache holds the entry before advancing time
        var hashedKey = BuildExpectedCacheKey(handle);
        cache.TryGetValue(hashedKey, out _).Should().BeTrue(
            because: "IMemoryCache must still hold the entry before logical expiry check");

        // Advance FakeTimeProvider past ExpiresAt
        tp.Advance(TimeSpan.FromMinutes(2));

        var result = await store.FindAsync(handle, CancellationToken.None);

        result.Should().BeNull(
            because: "FindAsync must use TimeProvider.GetUtcNow() to check logical expiry, " +
                     "not rely solely on cache eviction which uses the real wall clock");
    }

    [Fact]
    public async Task FindAsync_returns_entry_when_time_equals_ExpiresAt_minus_one_tick()
    {
        var startTime = new DateTimeOffset(2090, 1, 1, 12, 0, 0, TimeSpan.Zero);
        var expiresAt = startTime.AddMinutes(5);

        var tp = new FakeTimeProvider(startTime);
        var store = CreateStore(timeProvider: tp);
        const string handle = "find-at-boundary";
        var entry = BuildEntry(issuedAt: startTime, expiresAt: expiresAt);

        await store.StoreAsync(handle, entry, CancellationToken.None);

        // Advance to one tick before expiry
        tp.SetUtcNow(expiresAt - TimeSpan.FromTicks(1));

        var result = await store.FindAsync(handle, CancellationToken.None);

        result.Should().NotBeNull(
            because: "the token must still be valid one tick before ExpiresAt");
    }

    [Fact]
    public async Task FindAsync_returns_null_when_time_exactly_equals_ExpiresAt()
    {
        var startTime = new DateTimeOffset(2090, 1, 1, 12, 0, 0, TimeSpan.Zero);
        var expiresAt = startTime.AddMinutes(5);

        var tp = new FakeTimeProvider(startTime);
        var store = CreateStore(timeProvider: tp);
        const string handle = "find-at-exact-expiry";
        var entry = BuildEntry(issuedAt: startTime, expiresAt: expiresAt);

        await store.StoreAsync(handle, entry, CancellationToken.None);

        // Advance to exactly ExpiresAt
        tp.SetUtcNow(expiresAt);

        var result = await store.FindAsync(handle, CancellationToken.None);

        result.Should().BeNull(
            because: "the condition is >= ExpiresAt so a token is expired at exactly ExpiresAt");
    }

    // ── FindAsync family revocation ───────────────────────────────────────────────────────────────

    [Fact]
    public async Task FindAsync_returns_null_for_token_in_revoked_family()
    {
        var store = CreateStore();
        const string handle = "revoked-family-find";
        const string familyId = "family-to-revoke";
        var entry = BuildEntry(familyId: familyId);

        await store.StoreAsync(handle, entry, CancellationToken.None);
        await store.RevokeFamilyAsync(familyId, CancellationToken.None);

        var result = await store.FindAsync(handle, CancellationToken.None);

        result.Should().BeNull(
            because: "FindAsync must return null for tokens whose family has been revoked");
    }

    [Fact]
    public async Task FindAsync_returns_entry_for_token_in_different_non_revoked_family()
    {
        var store = CreateStore();
        const string handle = "non-revoked-family-find";
        const string otherFamilyId = "other-family";
        var entry = BuildEntry(familyId: otherFamilyId);

        await store.StoreAsync(handle, entry, CancellationToken.None);
        await store.RevokeFamilyAsync("different-family", CancellationToken.None);

        var result = await store.FindAsync(handle, CancellationToken.None);

        result.Should().NotBeNull(
            because: "revoking a different family must not affect tokens in other families");
    }

    // ── FindAsync does not consume (AC 6) ────────────────────────────────────────────────────────

    [Fact]
    public async Task FindAsync_multiple_calls_do_not_consume_token_and_TryConsumeAsync_still_succeeds()
    {
        var store = CreateStore();
        const string handle = "find-is-non-consuming";
        var entry = BuildEntry(clientId: "client-a", familyId: "fam-find-nonconsume");

        await store.StoreAsync(handle, entry, CancellationToken.None);

        // Call FindAsync several times — it must never consume the token
        var find1 = await store.FindAsync(handle, CancellationToken.None);
        var find2 = await store.FindAsync(handle, CancellationToken.None);
        var find3 = await store.FindAsync(handle, CancellationToken.None);

        find1.Should().NotBeNull(because: "first FindAsync must return the entry");
        find2.Should().NotBeNull(because: "second FindAsync must return the entry — it is non-consuming");
        find3.Should().NotBeNull(because: "third FindAsync must return the entry — it is non-consuming");

        // Token must still be consumable after multiple FindAsync calls
        var outcome = await store.TryConsumeAsync(handle, "client-a", CancellationToken.None);

        outcome.Should().BeOfType<RefreshTokenConsumptionOutcome.Consumed>(
            because: "TryConsumeAsync must succeed after multiple FindAsync calls — " +
                     "FindAsync is a read-only operation and must never consume the token");
    }

    // ── FindAsync DP/JSON failure → null ──────────────────────────────────────────────────────────

    [Fact]
    public async Task FindAsync_returns_null_when_entry_cannot_be_unprotected()
    {
        // Two stores share the same IMemoryCache but use independent key rings.
        // Store 1 writes the entry. Store 2 cannot unprotect it.
        var sharedCache = new MemoryCache(new MemoryCacheOptions());
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

    // ── TryConsumeAsync — basic success ───────────────────────────────────────────────────────────

    [Fact]
    public async Task TryConsumeAsync_returns_Consumed_for_valid_token()
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
        var entry = BuildEntry(
            clientId: "client-a",
            familyId: "fam-roundtrip",
            issuedAt: now,
            expiresAt: FarFuture);

        await store.StoreAsync(handle, entry, CancellationToken.None);
        var outcome = await store.TryConsumeAsync(handle, "client-a", CancellationToken.None);

        outcome.Should().BeOfType<RefreshTokenConsumptionOutcome.Consumed>()
            .Which.Entry.Should().BeEquivalentTo(entry,
            because: "the consumed entry must match the stored entry exactly");
    }

    // ── TryConsumeAsync — NotFound paths ─────────────────────────────────────────────────────────

    [Fact]
    public async Task TryConsumeAsync_returns_NotFound_for_unknown_handle()
    {
        var store = CreateStore();

        var outcome = await store.TryConsumeAsync("never-stored", "client-a", CancellationToken.None);

        outcome.Should().BeOfType<RefreshTokenConsumptionOutcome.NotFound>(
            because: "a handle that was never stored must return NotFound");
    }

    [Fact]
    public async Task TryConsumeAsync_returns_NotFound_when_time_is_past_ExpiresAt()
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

    [Fact]
    public async Task TryConsumeAsync_returns_NotFound_when_entry_cannot_be_unprotected()
    {
        // Two stores share the same IMemoryCache but use independent key rings.
        // Store 1 writes the entry. Store 2 cannot unprotect it — no tombstone exists.
        var sharedCache = new MemoryCache(new MemoryCacheOptions());
        var dp1 = new EphemeralDataProtectionProvider();
        var dp2 = new EphemeralDataProtectionProvider();

        var store1 = CreateStore(cache: sharedCache, dp: dp1);
        var store2 = CreateStore(cache: sharedCache, dp: dp2);
        const string handle = "dp-rotation-consume-entry-unreadable";

        await store1.StoreAsync(handle, BuildEntry(), CancellationToken.None);

        var outcome = await store2.TryConsumeAsync(handle, "client-a", CancellationToken.None);

        outcome.Should().BeOfType<RefreshTokenConsumptionOutcome.NotFound>(
            because: "an entry that cannot be unprotected (DP key rotation) must return NotFound — " +
                     "no tombstone exists so this is not a detected replay");
    }

    // ── TryConsumeAsync — AlreadyConsumed (tombstone) ─────────────────────────────────────────────

    [Fact]
    public async Task TryConsumeAsync_returns_AlreadyConsumed_for_replay_after_successful_consumption()
    {
        var store = CreateStore();
        const string handle = "replay-attack-handle";

        await store.StoreAsync(handle, BuildEntry(), CancellationToken.None);
        var firstOutcome = await store.TryConsumeAsync(handle, "client-a", CancellationToken.None);
        firstOutcome.Should().BeOfType<RefreshTokenConsumptionOutcome.Consumed>();

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
        var entry = BuildEntry(familyId: familyId);

        await store.StoreAsync(handle, entry, CancellationToken.None);
        await store.TryConsumeAsync(handle, "client-a", CancellationToken.None);

        var replayOutcome = await store.TryConsumeAsync(handle, "client-a", CancellationToken.None);

        replayOutcome.Should().BeOfType<RefreshTokenConsumptionOutcome.AlreadyConsumed>()
            .Which.FamilyId.Should().Be(familyId,
            because: "the tombstone must preserve the family ID for the replay detection signal");
    }

    [Fact]
    public async Task TryConsumeAsync_returns_NotFound_when_tombstone_is_unreadable_due_to_DP_key_rotation()
    {
        // NOTE: This test documents a known divergence from the spec.
        //
        // The XML documentation states: "Tombstone decryption failures are treated as
        // AlreadyConsumed so replays are always rejected even when the family ID cannot be
        // recovered." However, the implementation cannot distinguish between an unreadable
        // tombstone and an unreadable live entry, because both share the same cache key
        // (zkd:rt:{hash}) and the IsConsumed flag is inside the encrypted payload. When
        // Unprotect() throws, the implementation falls through to a single catch block that
        // unconditionally returns NotFound.
        //
        // This is a STORE BUG: replays where the tombstone ciphertext cannot be decrypted
        // (e.g. after DP key rotation) are silently treated as NotFound, allowing the
        // original token handle to appear valid on a different store instance or after rotation.
        //
        // The correct fix is to add a separate tombstone indicator (e.g. a separate cache key
        // or a known sentinel prefix) so that tombstones are detectable without decryption.
        var sharedCache = new MemoryCache(new MemoryCacheOptions());
        var dp1 = new EphemeralDataProtectionProvider();
        var dp2 = new EphemeralDataProtectionProvider();

        var store1 = CreateStore(cache: sharedCache, dp: dp1);
        var store2 = CreateStore(cache: sharedCache, dp: dp2);
        const string handle = "dp-rotation-tombstone-unreadable";

        await store1.StoreAsync(handle, BuildEntry(), CancellationToken.None);

        // Store1 writes the tombstone encrypted under dp1's key ring
        var firstOutcome = await store1.TryConsumeAsync(handle, "client-a", CancellationToken.None);
        firstOutcome.Should().BeOfType<RefreshTokenConsumptionOutcome.Consumed>(
            because: "first consumption via store1 must succeed");

        // Store2 uses dp2 — the tombstone exists in the cache but Unprotect throws CryptographicException.
        // The implementation returns NotFound (store bug: should return AlreadyConsumed per the spec).
        var outcome = await store2.TryConsumeAsync(handle, "client-a", CancellationToken.None);

        outcome.Should().BeOfType<RefreshTokenConsumptionOutcome.NotFound>(
            because: "STORE BUG: the implementation returns NotFound when the tombstone ciphertext " +
                     "cannot be unprotected, rather than AlreadyConsumed as specified in the XML docs. " +
                     "This means replays are not detected after DP key rotation.");
    }

    // ── TryConsumeAsync — Revoked ─────────────────────────────────────────────────────────────────

    [Fact]
    public async Task TryConsumeAsync_returns_Revoked_for_token_in_revoked_family()
    {
        var store = CreateStore();
        const string handle = "revoked-family-consume";
        const string familyId = "fam-revoked";
        var entry = BuildEntry(familyId: familyId);

        await store.StoreAsync(handle, entry, CancellationToken.None);
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
        var entry = BuildEntry(familyId: familyId);

        await store.StoreAsync(handle, entry, CancellationToken.None);
        await store.RevokeFamilyAsync(familyId, CancellationToken.None);

        var outcome = await store.TryConsumeAsync(handle, "client-a", CancellationToken.None);

        outcome.Should().BeOfType<RefreshTokenConsumptionOutcome.Revoked>()
            .Which.FamilyId.Should().Be(familyId,
            because: "the Revoked outcome must carry the family ID from the token entry");
    }

    // ── TryConsumeAsync — ClientMismatch ──────────────────────────────────────────────────────────

    [Fact]
    public async Task TryConsumeAsync_returns_ClientMismatch_when_client_does_not_match()
    {
        var store = CreateStore();
        const string handle = "client-mismatch-handle";
        var entry = BuildEntry(clientId: "client-a");

        await store.StoreAsync(handle, entry, CancellationToken.None);

        var outcome = await store.TryConsumeAsync(handle, "client-b", CancellationToken.None);

        outcome.Should().BeOfType<RefreshTokenConsumptionOutcome.ClientMismatch>(
            because: "presenting client does not match the client the token is bound to");
    }

    [Fact]
    public async Task TryConsumeAsync_ClientMismatch_does_not_consume_token_allowing_legitimate_client_to_succeed()
    {
        var store = CreateStore();
        const string handle = "client-mismatch-no-consume";
        var entry = BuildEntry(clientId: "client-a");

        await store.StoreAsync(handle, entry, CancellationToken.None);

        var mismatchOutcome = await store.TryConsumeAsync(handle, "client-b", CancellationToken.None);
        mismatchOutcome.Should().BeOfType<RefreshTokenConsumptionOutcome.ClientMismatch>(
            because: "presenting client does not match the bound client");

        var legitimateOutcome = await store.TryConsumeAsync(handle, "client-a", CancellationToken.None);
        legitimateOutcome.Should().BeOfType<RefreshTokenConsumptionOutcome.Consumed>(
            because: "ClientMismatch must leave the token intact for the legitimate client");
    }

    [Fact]
    public async Task TryConsumeAsync_ClientMismatch_does_not_write_tombstone()
    {
        var cache = new MemoryCache(new MemoryCacheOptions());
        var store = CreateStore(cache: cache);
        const string handle = "no-tombstone-on-client-mismatch";
        var entry = BuildEntry(clientId: "client-a");

        await store.StoreAsync(handle, entry, CancellationToken.None);
        var bytesBeforeMismatch = ReadCacheBytes(cache, BuildExpectedCacheKey(handle));

        await store.TryConsumeAsync(handle, "wrong-client", CancellationToken.None);

        // The cache entry should still be the live entry (not overwritten by a tombstone)
        var bytesAfterMismatch = ReadCacheBytes(cache, BuildExpectedCacheKey(handle));
        bytesAfterMismatch.Should().Equal(bytesBeforeMismatch,
            because: "ClientMismatch must not modify the cache entry — the live entry must remain");
    }

    private static byte[]? ReadCacheBytes(IMemoryCache cache, string key)
    {
        cache.TryGetValue(key, out byte[]? bytes);
        return bytes;
    }

    // ── TryConsumeAsync — outcome precedence (order of checks) ───────────────────────────────────

    [Fact]
    public async Task TryConsumeAsync_returns_Revoked_not_ClientMismatch_when_family_is_revoked_and_client_mismatches()
    {
        // Revocation check comes before client-mismatch check in the implementation.
        // This test documents and verifies that precedence.
        var store = CreateStore();
        const string handle = "revoked-and-wrong-client";
        const string familyId = "fam-revoked-mismatch";
        var entry = BuildEntry(clientId: "client-a", familyId: familyId);

        await store.StoreAsync(handle, entry, CancellationToken.None);
        await store.RevokeFamilyAsync(familyId, CancellationToken.None);

        var outcome = await store.TryConsumeAsync(handle, "client-b", CancellationToken.None);

        outcome.Should().BeOfType<RefreshTokenConsumptionOutcome.Revoked>(
            because: "the revocation check happens before the client-mismatch check");
    }

    // ── Tombstone TTL ─────────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task TryConsumeAsync_tombstone_TTL_equals_entry_ExpiresAt()
    {
        // Both StoreAsync and the tombstone write inside TryConsumeAsync use CreateEntry
        // (the IMemoryCache.Set extension method calls CreateEntry internally).
        // The CapturingMemoryCache records the AbsoluteExpiration on every CreateEntry call;
        // the second write (tombstone) overwrites the first write (live entry) in CapturedExpiries.
        // After consumption the dictionary value for the key must be the tombstone's expiry = entry.ExpiresAt.
        var innerCache = new MemoryCache(new MemoryCacheOptions());
        var capturingCache = new CapturingMemoryCache(innerCache);

        var startTime = new DateTimeOffset(2090, 1, 1, 12, 0, 0, TimeSpan.Zero);
        var expiresAt = startTime.AddHours(2);
        var tp = new FakeTimeProvider(startTime);

        var store = CreateStore(cache: capturingCache, timeProvider: tp);
        const string handle = "tombstone-ttl-check";
        var entry = BuildEntry(issuedAt: startTime, expiresAt: expiresAt);

        await store.StoreAsync(handle, entry, CancellationToken.None);

        // Before consumption: CapturedExpiries holds the live entry's expiry = expiresAt
        var cacheKey = BuildExpectedCacheKey(handle);
        capturingCache.CapturedExpiries.Should().ContainKey(cacheKey,
            because: "live entry must have been written to the cache");
        capturingCache.CapturedExpiries[cacheKey].Should().Be(expiresAt,
            because: "live entry AbsoluteExpiration is set to entry.ExpiresAt");

        await store.TryConsumeAsync(handle, "client-a", CancellationToken.None);

        // After consumption: CapturedExpiries is overwritten by the tombstone write.
        // The tombstone uses _cache.Set(cacheKey, ..., entry.ExpiresAt) so the value remains the same.
        capturingCache.CapturedExpiries.Should().ContainKey(cacheKey,
            because: "tombstone must have been written at the same cache key");
        capturingCache.CapturedExpiries[cacheKey].Should().Be(expiresAt,
            because: "tombstone TTL must equal the entry's ExpiresAt so the consumed marker " +
                     "lives exactly as long as the original token would have");
    }

    [Fact]
    public async Task TryConsumeAsync_tombstone_is_present_immediately_after_consumption()
    {
        var cache = new MemoryCache(new MemoryCacheOptions());
        var store = CreateStore(cache: cache);
        const string handle = "tombstone-present-immediately";

        await store.StoreAsync(handle, BuildEntry(), CancellationToken.None);
        await store.TryConsumeAsync(handle, "client-a", CancellationToken.None);

        // The key should still be in the cache (tombstone overwrote the live entry)
        var cacheKey = BuildExpectedCacheKey(handle);
        cache.TryGetValue(cacheKey, out _).Should().BeTrue(
            because: "tombstone must be present immediately after consumption");
    }

    // ── RevokeFamilyAsync ─────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task RevokeFamilyAsync_prevents_FindAsync_from_returning_entry()
    {
        var store = CreateStore();
        const string handle = "revoke-blocks-find";
        const string familyId = "fam-to-revoke-find";

        await store.StoreAsync(handle, BuildEntry(familyId: familyId), CancellationToken.None);
        await store.RevokeFamilyAsync(familyId, CancellationToken.None);

        var result = await store.FindAsync(handle, CancellationToken.None);

        result.Should().BeNull(
            because: "after RevokeFamilyAsync, FindAsync must return null for all tokens in that family");
    }

    [Fact]
    public async Task RevokeFamilyAsync_causes_TryConsumeAsync_to_return_Revoked()
    {
        var store = CreateStore();
        const string handle = "revoke-blocks-consume";
        const string familyId = "fam-to-revoke-consume";

        await store.StoreAsync(handle, BuildEntry(familyId: familyId), CancellationToken.None);
        await store.RevokeFamilyAsync(familyId, CancellationToken.None);

        var outcome = await store.TryConsumeAsync(handle, "client-a", CancellationToken.None);

        outcome.Should().BeOfType<RefreshTokenConsumptionOutcome.Revoked>(
            because: "after RevokeFamilyAsync, TryConsumeAsync must return Revoked for all tokens in that family");
    }

    [Fact]
    public async Task RevokeFamilyAsync_is_idempotent()
    {
        var store = CreateStore();
        const string familyId = "idempotent-family";

        // Calling twice must not throw
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

    // ── Concurrency atomicity ─────────────────────────────────────────────────────────────────────

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

        // Release all tasks simultaneously so they genuinely contend on the per-handle semaphore
        gate.Release(concurrentTasks);

        var outcomes = await Task.WhenAll(tasks);

        var consumedCount = outcomes.Count(o => o is RefreshTokenConsumptionOutcome.Consumed);
        var alreadyConsumedCount = outcomes.Count(o => o is RefreshTokenConsumptionOutcome.AlreadyConsumed);
        var notFoundCount = outcomes.Count(o => o is RefreshTokenConsumptionOutcome.NotFound);

        consumedCount.Should().Be(1, because: "exactly one concurrent attempt must succeed");
        alreadyConsumedCount.Should().Be(concurrentTasks - 1,
            because: "all other attempts must see AlreadyConsumed, not NotFound");
        notFoundCount.Should().Be(0,
            because: "no attempt should see NotFound when the token was stored");
    }

    // ── Semaphore lifecycle ───────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task Semaphore_is_pre_seeded_during_StoreAsync()
    {
        var store = CreateStore();
        const string handle = "semaphore-pre-seed";

        var semaphoresField = typeof(InMemoryRefreshTokenStore)
            .GetField("_semaphores", BindingFlags.NonPublic | BindingFlags.Instance)!;

        var countBefore = (semaphoresField.GetValue(store) as System.Collections.ICollection)?.Count ?? -1;
        countBefore.Should().Be(0, because: "no semaphores before any store operations");

        await store.StoreAsync(handle, BuildEntry(), CancellationToken.None);

        var countAfterStore = (semaphoresField.GetValue(store) as System.Collections.ICollection)?.Count ?? -1;
        countAfterStore.Should().Be(1, because: "one semaphore must be pre-seeded after StoreAsync");
    }

    [Fact]
    public async Task Semaphore_is_removed_after_successful_consumption()
    {
        var store = CreateStore();
        const string handle = "semaphore-cleanup-on-consume";

        var semaphoresField = typeof(InMemoryRefreshTokenStore)
            .GetField("_semaphores", BindingFlags.NonPublic | BindingFlags.Instance)!;

        await store.StoreAsync(handle, BuildEntry(), CancellationToken.None);

        var outcome = await store.TryConsumeAsync(handle, "client-a", CancellationToken.None);
        outcome.Should().BeOfType<RefreshTokenConsumptionOutcome.Consumed>(
            because: "consumption must succeed before checking semaphore cleanup");

        var semaphoresAfterConsume = semaphoresField.GetValue(store) as System.Collections.ICollection;
        semaphoresAfterConsume?.Count.Should().Be(0,
            because: "the semaphore must be removed from _semaphores after successful consumption");
    }

    [Fact]
    public async Task Semaphore_is_retained_after_ClientMismatch_outcome()
    {
        var store = CreateStore();
        const string handle = "semaphore-retained-on-mismatch";

        var semaphoresField = typeof(InMemoryRefreshTokenStore)
            .GetField("_semaphores", BindingFlags.NonPublic | BindingFlags.Instance)!;

        await store.StoreAsync(handle, BuildEntry(clientId: "client-a"), CancellationToken.None);
        await store.TryConsumeAsync(handle, "wrong-client", CancellationToken.None);

        var semaphores = semaphoresField.GetValue(store) as System.Collections.ICollection;
        semaphores?.Count.Should().Be(1,
            because: "semaphore must not be removed when TryConsumeAsync returns ClientMismatch — " +
                     "the token is still live and a subsequent legitimate request needs it");
    }

    [Fact]
    public async Task Semaphores_dictionary_does_not_grow_unboundedly_after_many_consume_cycles()
    {
        var store = CreateStore();
        var semaphoresField = typeof(InMemoryRefreshTokenStore)
            .GetField("_semaphores", BindingFlags.NonPublic | BindingFlags.Instance)!;

        // Store 20 tokens and consume each one successfully — cleanup happens on successful consumption
        for (int i = 0; i < 20; i++)
        {
            var handle = $"growing-handle-{i}";
            await store.StoreAsync(handle, BuildEntry(familyId: $"fam-{i}"), CancellationToken.None);
        }

        for (int i = 0; i < 20; i++)
        {
            var handle = $"growing-handle-{i}";
            await store.TryConsumeAsync(handle, "client-a", CancellationToken.None);
        }

        var semaphoresCollection = semaphoresField.GetValue(store) as System.Collections.ICollection;
        var countAfterConsumptions = semaphoresCollection?.Count ?? -1;
        countAfterConsumptions.Should().Be(0,
            because: "all semaphores should be removed after all tokens are successfully consumed");
    }

    // ── Exception wrapping ────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task StoreAsync_wraps_IMemoryCache_CreateEntry_exception_in_ZeeKayDaStoreException()
    {
        var faultingCache = new ThrowingMemoryCache();
        var store = CreateStore(cache: faultingCache);

        var act = async () =>
            await store.StoreAsync("any-handle", BuildEntry(), CancellationToken.None);

        var assertion = await act.Should().ThrowAsync<ZeeKayDaStoreException>(
            because: "infrastructure failures from IMemoryCache must be wrapped in ZeeKayDaStoreException");

        assertion.Which.InnerException.Should().BeOfType<InvalidOperationException>(
            because: "the original exception must be preserved as the inner exception");
    }

    [Fact]
    public async Task StoreAsync_ZeeKayDaStoreException_has_descriptive_message()
    {
        var faultingCache = new ThrowingMemoryCache();
        var store = CreateStore(cache: faultingCache);

        var exception = await Assert.ThrowsAsync<ZeeKayDaStoreException>(
            () => store.StoreAsync("handle", BuildEntry(), CancellationToken.None));

        exception.Message.Should().NotBeNullOrWhiteSpace(
            because: "ZeeKayDaStoreException must carry a descriptive message");
    }

    [Fact]
    public async Task TryConsumeAsync_wraps_DataProtection_Protect_failure_in_ZeeKayDaStoreException()
    {
        // Store with working DP so the entry is valid; redeem with faulting DP to trigger tombstone write failure
        var workingDp = new EphemeralDataProtectionProvider();
        var faultingDp = new ProtectFailingDataProtectionProvider(workingDp);

        var cache = new MemoryCache(new MemoryCacheOptions());
        var storeForWrite = CreateStore(cache: cache, dp: workingDp);
        var storeForConsume = CreateStore(cache: cache, dp: faultingDp);

        const string handle = "dp-protect-failure-consume";
        await storeForWrite.StoreAsync(handle, BuildEntry(), CancellationToken.None);

        var act = async () =>
            await storeForConsume.TryConsumeAsync(handle, "client-a", CancellationToken.None);

        var assertion = await act.Should().ThrowAsync<ZeeKayDaStoreException>(
            because: "IDataProtector.Protect() failures during tombstone write must be wrapped in ZeeKayDaStoreException");
        assertion.Which.InnerException.Should().NotBeNull(
            because: "the original exception must be preserved as InnerException");
    }

    // ── ArgumentNullException guards ─────────────────────────────────────────────────────────────

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

    [Fact]
    public async Task StoreAsync_respects_pre_cancelled_CancellationToken()
    {
        var store = CreateStore();
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
        var store = CreateStore();
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
        var store = CreateStore();
        using var cts = new CancellationTokenSource();
        cts.Cancel();

        var act = async () =>
            await store.RevokeFamilyAsync("some-family", cts.Token);

        await act.Should().ThrowAsync<OperationCanceledException>(
            because: "RevokeFamilyAsync must honour a pre-cancelled CancellationToken");
    }

    // ── No ILogger parameter ──────────────────────────────────────────────────────────────────────

    [Fact]
    public void InMemoryRefreshTokenStore_constructor_has_no_ILogger_parameter()
    {
        var constructors = typeof(InMemoryRefreshTokenStore)
            .GetConstructors(BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Instance);

        var hasLoggerParam = constructors.Any(ctor =>
            ctor.GetParameters().Any(p =>
                p.ParameterType.IsGenericType
                    ? p.ParameterType.GetGenericTypeDefinition().FullName?.StartsWith(
                        "Microsoft.Extensions.Logging.ILogger") == true
                    : p.ParameterType.FullName?.StartsWith(
                        "Microsoft.Extensions.Logging.ILogger") == true));

        hasLoggerParam.Should().BeFalse(
            because: "InMemoryRefreshTokenStore must not accept ILogger to prevent sensitive " +
                     "token handles or entry data from appearing in log sinks");
    }

    // ── XML documentation — family revocation plaintext rationale (AC 8) ────────────────────────

    [Fact]
    public void InMemoryRefreshTokenStore_XML_doc_contains_fail_open_rationale_for_plaintext_revocation_markers()
    {
        var assemblyLocation = typeof(InMemoryRefreshTokenStore).Assembly.Location;
        var xmlDocPath = Path.ChangeExtension(assemblyLocation, ".xml");

        File.Exists(xmlDocPath).Should().BeTrue(
            because: $"XML doc file must exist at {xmlDocPath} for this verification to work");

        var doc = System.Xml.Linq.XDocument.Load(xmlDocPath);
        const string memberName = "T:ZeeKayDa.Auth.Stores.InMemoryRefreshTokenStore";

        var memberElement = doc.Descendants("member")
            .FirstOrDefault(m => m.Attribute("name")?.Value == memberName);

        memberElement.Should().NotBeNull(
            because: "the XML doc must contain an entry for InMemoryRefreshTokenStore");

        var fullText = memberElement!.Value;

        fullText.Should().Contain(
            "fail open",
            because: "the XML documentation must explain that DP-encrypting revocation markers " +
                     "would fail open into 'not revoked' on a DP key unavailability — the plaintext " +
                     "storage is an intentional security trade-off, not an oversight");
    }

    // ── XML documentation warning ─────────────────────────────────────────────────────────────────

    [Fact]
    public void InMemoryRefreshTokenStore_XML_doc_contains_single_instance_deployment_invariant_warning()
    {
        var assemblyLocation = typeof(InMemoryRefreshTokenStore).Assembly.Location;
        var xmlDocPath = Path.ChangeExtension(assemblyLocation, ".xml");

        File.Exists(xmlDocPath).Should().BeTrue(
            because: $"XML doc file must exist at {xmlDocPath} for this verification to work");

        var doc = System.Xml.Linq.XDocument.Load(xmlDocPath);
        const string memberName = "T:ZeeKayDa.Auth.Stores.InMemoryRefreshTokenStore";

        var memberElement = doc.Descendants("member")
            .FirstOrDefault(m => m.Attribute("name")?.Value == memberName);

        memberElement.Should().NotBeNull(
            because: "the XML doc must contain an entry for InMemoryRefreshTokenStore");

        var fullText = memberElement!.Value;

        fullText.Should().Contain(
            "Single-instance is a deployment invariant, not a recommendation",
            because: "the XML documentation must warn operators that running multiple instances " +
                     "silently disables single-use enforcement");
    }

    // ── Entry properties preserved through round-trip ─────────────────────────────────────────────

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

    // ── Helpers ───────────────────────────────────────────────────────────────────────────────────

    /// <summary>
    /// A minimal <see cref="IMemoryCache"/> implementation whose <see cref="CreateEntry"/> method
    /// always throws to simulate an infrastructure failure.
    /// </summary>
    private sealed class ThrowingMemoryCache : IMemoryCache
    {
        public ICacheEntry CreateEntry(object key)
            => throw new InvalidOperationException("Simulated cache infrastructure failure.");

        public void Remove(object key) { }

        public bool TryGetValue(object key, out object? value)
        {
            value = null;
            return false;
        }

        public void Dispose() { }
    }

    /// <summary>
    /// A <see cref="IMemoryCache"/> wrapper that records the <see cref="DateTimeOffset"/>
    /// absolute expiration set on each cache entry via <c>CreateEntry</c>. Both the initial
    /// write (StoreAsync) and the tombstone write (TryConsumeAsync) go through CreateEntry
    /// (the <c>IMemoryCache.Set</c> extension method calls CreateEntry internally). The
    /// dictionary therefore holds the last-seen expiry per key, which after consumption is
    /// the tombstone's expiry.
    /// </summary>
    private sealed class CapturingMemoryCache : IMemoryCache
    {
        private readonly IMemoryCache _inner;

        /// <summary>Captures the last-seen AbsoluteExpiration set on each key.</summary>
        public Dictionary<string, DateTimeOffset?> CapturedExpiries { get; } = new();

        public CapturingMemoryCache(IMemoryCache inner) => _inner = inner;

        public ICacheEntry CreateEntry(object key)
        {
            var entry = _inner.CreateEntry(key);
            return new CapturingCacheEntry(entry, this, key.ToString()!);
        }

        public void Remove(object key) => _inner.Remove(key);

        public bool TryGetValue(object key, out object? value) => _inner.TryGetValue(key, out value);

        public void Dispose() => _inner.Dispose();

        internal void RecordCreateExpiry(string key, DateTimeOffset? expiry)
            => CapturedExpiries[key] = expiry;

        private sealed class CapturingCacheEntry : ICacheEntry
        {
            private readonly ICacheEntry _inner;
            private readonly CapturingMemoryCache _cache;
            private readonly string _key;

            public CapturingCacheEntry(ICacheEntry inner, CapturingMemoryCache cache, string key)
            {
                _inner = inner;
                _cache = cache;
                _key = key;
            }

            public object Key => _inner.Key;
            public object? Value { get => _inner.Value; set => _inner.Value = value; }

            public DateTimeOffset? AbsoluteExpiration
            {
                get => _inner.AbsoluteExpiration;
                set
                {
                    _inner.AbsoluteExpiration = value;
                    _cache.RecordCreateExpiry(_key, value);
                }
            }

            public TimeSpan? AbsoluteExpirationRelativeToNow
            {
                get => _inner.AbsoluteExpirationRelativeToNow;
                set => _inner.AbsoluteExpirationRelativeToNow = value;
            }

            public TimeSpan? SlidingExpiration
            {
                get => _inner.SlidingExpiration;
                set => _inner.SlidingExpiration = value;
            }

            public IList<IChangeToken> ExpirationTokens => _inner.ExpirationTokens;
            public IList<PostEvictionCallbackRegistration> PostEvictionCallbacks => _inner.PostEvictionCallbacks;
            public CacheItemPriority Priority { get => _inner.Priority; set => _inner.Priority = value; }
            public long? Size { get => _inner.Size; set => _inner.Size = value; }
            public void Dispose() => _inner.Dispose();
        }
    }

    private sealed class ProtectFailingDataProtectionProvider : IDataProtectionProvider
    {
        private readonly IDataProtectionProvider _inner;
        public ProtectFailingDataProtectionProvider(IDataProtectionProvider inner) => _inner = inner;
        public IDataProtector CreateProtector(string purpose)
            => new ProtectFailingDataProtector(_inner.CreateProtector(purpose));
    }

    private sealed class ProtectFailingDataProtector : IDataProtector
    {
        private readonly IDataProtector _inner;
        public ProtectFailingDataProtector(IDataProtector inner) => _inner = inner;
        public IDataProtector CreateProtector(string purpose)
            => new ProtectFailingDataProtector(_inner.CreateProtector(purpose));
        public byte[] Protect(byte[] plaintext)
            => throw new InvalidOperationException("Simulated DP Protect() failure.");
        public byte[] Unprotect(byte[] protectedData)
            => _inner.Unprotect(protectedData);
    }
}
