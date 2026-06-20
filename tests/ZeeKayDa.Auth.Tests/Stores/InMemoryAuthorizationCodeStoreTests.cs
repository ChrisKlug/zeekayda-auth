using System.Buffers.Text;
using System.Collections.Concurrent;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Xml.Linq;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Primitives;
using Microsoft.Extensions.Time.Testing;
using ZeeKayDa.Auth.Authorization;
using ZeeKayDa.Auth.Stores;

namespace ZeeKayDa.Auth.Tests.Stores;

/// <summary>
/// Tests for <see cref="InMemoryAuthorizationCodeStore"/> covering all 12 acceptance criteria.
/// </summary>
/// <remarks>
/// IMPORTANT: IMemoryCache uses the real wall clock for AbsoluteExpiration evaluation, not
/// the injected TimeProvider. Tests that rely on IMemoryCache actually holding an entry must
/// therefore set ExpiresAt to a date far in the real future (e.g. year 2099). Tests that
/// exercise the logical expiry check (AC 4) use a FakeTimeProvider initialised at a real-future
/// start time, then advance it past ExpiresAt.
/// </remarks>
public sealed class InMemoryAuthorizationCodeStoreTests
{
    /// <summary>
    /// A far-future date used as ExpiresAt when the test needs IMemoryCache to actually
    /// hold the entry (since IMemoryCache uses the real wall clock for eviction).
    /// </summary>
    private static readonly DateTimeOffset FarFuture = new(2099, 1, 1, 0, 0, 0, TimeSpan.Zero);

    // ── Factory helpers ───────────────────────────────────────────────────────────────────────────

    private static InMemoryAuthorizationCodeStore CreateStore(
        IMemoryCache? cache = null,
        IDataProtectionProvider? dp = null,
        InMemoryTokenStoreOptions? storeOptions = null,
        AuthorizationServerOptions? serverOptions = null,
        TimeProvider? timeProvider = null)
    {
        return new InMemoryAuthorizationCodeStore(
            cache ?? new MemoryCache(new MemoryCacheOptions()),
            dp ?? new EphemeralDataProtectionProvider(),
            new OptionsWrapper<InMemoryTokenStoreOptions>(storeOptions ?? new InMemoryTokenStoreOptions()),
            new OptionsWrapper<AuthorizationServerOptions>(serverOptions ?? new AuthorizationServerOptions()),
            timeProvider ?? TimeProvider.System);
    }

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

    /// <summary>
    /// Replicates the exact key derivation used inside <see cref="InMemoryAuthorizationCodeStore"/>
    /// so cache keys can be verified without access to private methods.
    /// </summary>
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

    // ── AC 1 — Cache key scheme ───────────────────────────────────────────────────────────────────

    [Fact]
    public async Task StoreAsync_writes_entry_under_hashed_key_not_raw_handle()
    {
        var cache = new MemoryCache(new MemoryCacheOptions());
        var store = CreateStore(cache: cache);
        const string code = "raw-handle-12345";

        await store.StoreAsync(code, BuildEntry(), CancellationToken.None);

        var expectedKey = BuildExpectedEntryKey(code);
        cache.TryGetValue(expectedKey, out _).Should().BeTrue(
            because: "entry must be stored under the hashed key zkd:code:{hash}");
        cache.TryGetValue(code, out _).Should().BeFalse(
            because: "the raw code handle must never be used as a cache key");
    }

    [Fact]
    public async Task TryRedeemAsync_writes_tombstone_under_hashed_redeemed_key()
    {
        var cache = new MemoryCache(new MemoryCacheOptions());
        // TimeProvider.System so cache AbsoluteExpiration is consistent with store's time check
        var store = CreateStore(cache: cache);
        const string code = "my-code-for-tombstone";

        await store.StoreAsync(code, BuildEntry(), CancellationToken.None);
        await store.TryRedeemAsync(code, "client-a", "family-1", CancellationToken.None);

        var expectedTombstoneKey = BuildExpectedTombstoneKey(code);
        cache.TryGetValue(expectedTombstoneKey, out _).Should().BeTrue(
            because: "tombstone must be stored under the hashed key zkd:code:{hash}:redeemed");
        cache.TryGetValue(code + ":redeemed", out _).Should().BeFalse(
            because: "the raw code handle must never appear in tombstone keys");
    }

    [Fact]
    public async Task StoreAsync_does_not_write_raw_handle_as_any_cache_key()
    {
        var cache = new MemoryCache(new MemoryCacheOptions());
        var store = CreateStore(cache: cache);
        const string code = "super-secret-raw-handle";

        await store.StoreAsync(code, BuildEntry(), CancellationToken.None);

        cache.TryGetValue(code, out _).Should().BeFalse(
            because: "the raw handle must never be used as a cache key");
    }

    // ── AC 2 — Data Protection encryption ────────────────────────────────────────────────────────

    [Fact]
    public async Task StoreAsync_value_in_cache_is_not_plain_json()
    {
        var cache = new MemoryCache(new MemoryCacheOptions());
        var store = CreateStore(cache: cache);
        const string code = "code-for-encryption-check";

        await store.StoreAsync(code, BuildEntry(), CancellationToken.None);

        var hashedKey = BuildExpectedEntryKey(code);
        cache.TryGetValue(hashedKey, out byte[]? rawBytes).Should().BeTrue();
        rawBytes.Should().NotBeNull();

        // Attempt to deserialise the raw bytes as UTF-8 JSON. Because the bytes are
        // Data Protection-encrypted ciphertext, this must either throw or produce null.
        AuthorizationCodeEntry? deserialized = null;
        try
        {
            var asText = Encoding.UTF8.GetString(rawBytes!);
            deserialized = System.Text.Json.JsonSerializer.Deserialize<AuthorizationCodeEntry>(
                asText, new System.Text.Json.JsonSerializerOptions(System.Text.Json.JsonSerializerDefaults.Web));
        }
        catch
        {
            // Expected — ciphertext is not valid JSON
        }

        deserialized.Should().BeNull(
            because: "stored bytes are encrypted ciphertext, not plain JSON");
    }

    // ── AC 3 — Concurrency atomicity ──────────────────────────────────────────────────────────────

    [Fact]
    public async Task TryRedeemAsync_exactly_one_Redeemed_under_high_concurrency()
    {
        var store = CreateStore();
        const string code = "concurrent-code";

        await store.StoreAsync(code, BuildEntry(), CancellationToken.None);

        const int concurrentTasks = 100;
        using var gate = new SemaphoreSlim(0, concurrentTasks);

        var tasks = Enumerable.Range(0, concurrentTasks)
            .Select(_ => Task.Run(async () =>
            {
                await gate.WaitAsync();
                return await store.TryRedeemAsync(code, "client-a", "family-concurrent", CancellationToken.None);
            }))
            .ToArray();

        // Release all tasks simultaneously so they genuinely contend on the per-handle semaphore
        gate.Release(concurrentTasks);

        var outcomes = await Task.WhenAll(tasks);

        var redeemedCount = outcomes.Count(o => o is AuthorizationCodeRedemptionOutcome.Redeemed);
        var alreadyRedeemedCount = outcomes.Count(o => o is AuthorizationCodeRedemptionOutcome.AlreadyRedeemed);
        var notFoundCount = outcomes.Count(o => o is AuthorizationCodeRedemptionOutcome.NotFound);

        redeemedCount.Should().Be(1, because: "exactly one concurrent attempt must succeed");
        alreadyRedeemedCount.Should().Be(concurrentTasks - 1,
            because: "all other attempts must see AlreadyRedeemed, not NotFound");
        notFoundCount.Should().Be(0,
            because: "no attempt should see NotFound when the code was stored");
    }

    // ── AC 4 — Logical expiry via TimeProvider ────────────────────────────────────────────────────

    [Fact]
    public async Task TryRedeemAsync_returns_NotFound_when_time_is_past_ExpiresAt_even_if_cache_still_holds_entry()
    {
        // Strategy: use a FakeTimeProvider starting at a real-future point, so that
        // IMemoryCache also considers the entry valid at store time. Then advance the
        // FakeTimeProvider past ExpiresAt without triggering real-clock eviction.
        var startTime = new DateTimeOffset(2090, 1, 1, 12, 0, 0, TimeSpan.Zero);
        var expiresAt = startTime.AddMinutes(1);

        // ExpiresAt = 2090-01-01 12:01 — far in the real future so IMemoryCache won't evict
        var tp = new FakeTimeProvider(startTime);
        var cache = new MemoryCache(new MemoryCacheOptions());
        var store = CreateStore(cache: cache, timeProvider: tp);
        const string code = "expiry-check-code";
        var entry = BuildEntry(issuedAt: startTime, expiresAt: expiresAt);

        await store.StoreAsync(code, entry, CancellationToken.None);

        // IMemoryCache should hold the entry (AbsoluteExpiration is in the real future)
        var hashedKey = BuildExpectedEntryKey(code);
        cache.TryGetValue(hashedKey, out _).Should().BeTrue(
            because: "IMemoryCache must still hold the entry before logical expiry check");

        // Advance FakeTimeProvider past ExpiresAt — real clock doesn't move, so cache won't evict
        tp.Advance(TimeSpan.FromMinutes(2));

        // The store's logical expiry check uses TimeProvider.GetUtcNow() — must return NotFound
        var outcome = await store.TryRedeemAsync(code, "client-a", "family-1", CancellationToken.None);

        outcome.Should().BeOfType<AuthorizationCodeRedemptionOutcome.NotFound>(
            because: "the store must use TimeProvider.GetUtcNow() to check logical expiry, " +
                     "not rely solely on cache eviction — which uses the real wall clock");
    }

    // ── AC 5 — ClientMismatch does not consume the code ───────────────────────────────────────────

    [Fact]
    public async Task TryRedeemAsync_ClientMismatch_does_not_consume_code_allowing_legitimate_client_to_redeem()
    {
        var store = CreateStore();
        const string code = "client-mismatch-code";

        await store.StoreAsync(code, BuildEntry(clientId: "client-a"), CancellationToken.None);

        var mismatchOutcome = await store.TryRedeemAsync(code, "client-b", "family-wrong", CancellationToken.None);
        mismatchOutcome.Should().BeOfType<AuthorizationCodeRedemptionOutcome.ClientMismatch>(
            because: "presenting client does not match the bound client");

        var redeemedOutcome = await store.TryRedeemAsync(code, "client-a", "family-correct", CancellationToken.None);
        redeemedOutcome.Should().BeOfType<AuthorizationCodeRedemptionOutcome.Redeemed>(
            because: "ClientMismatch must leave the code intact for the legitimate client");
    }

    [Fact]
    public async Task TryRedeemAsync_ClientMismatch_does_not_write_tombstone()
    {
        var cache = new MemoryCache(new MemoryCacheOptions());
        var store = CreateStore(cache: cache);
        const string code = "no-tombstone-on-mismatch";

        await store.StoreAsync(code, BuildEntry(clientId: "client-a"), CancellationToken.None);
        await store.TryRedeemAsync(code, "wrong-client", "family-x", CancellationToken.None);

        var tombstoneKey = BuildExpectedTombstoneKey(code);
        cache.TryGetValue(tombstoneKey, out _).Should().BeFalse(
            because: "ClientMismatch must not write a tombstone");
    }

    // ── AC 6 — Tombstone TTL = RefreshTokenLifetime ──────────────────────────────────────────────

    [Fact]
    public async Task TryRedeemAsync_tombstone_exists_immediately_after_redemption_case_A_RefreshTokenLifetime_longer()
    {
        var cache = new MemoryCache(new MemoryCacheOptions());
        var serverOptions = new AuthorizationServerOptions();
        serverOptions.TokenEndpoint.RefreshTokenLifetime = TimeSpan.FromDays(14);
        var store = CreateStore(cache: cache, serverOptions: serverOptions);
        const string code = "tombstone-ttl-case-a";

        await store.StoreAsync(code, BuildEntry(), CancellationToken.None);
        await store.TryRedeemAsync(code, "client-a", "family-a", CancellationToken.None);

        var tombstoneKey = BuildExpectedTombstoneKey(code);
        cache.TryGetValue(tombstoneKey, out _).Should().BeTrue(
            because: "tombstone must be present immediately after redemption");
    }

    [Fact]
    public async Task TryRedeemAsync_tombstone_TTL_is_RefreshTokenLifetime_regardless_of_remaining()
    {
        // The tombstone TTL is always RefreshTokenLifetime, even when remaining > RefreshTokenLifetime.
        var cache = new MemoryCache(new MemoryCacheOptions());
        var refreshTokenLifetime = TimeSpan.FromHours(1);
        var serverOptions = new AuthorizationServerOptions();
        serverOptions.TokenEndpoint.RefreshTokenLifetime = refreshTokenLifetime;

        var startTime = new DateTimeOffset(2090, 1, 1, 12, 0, 0, TimeSpan.Zero);
        var tp = new FakeTimeProvider(startTime);
        var capturingCache = new CapturingMemoryCache(cache);

        var store = CreateStore(cache: capturingCache, serverOptions: serverOptions, timeProvider: tp);
        const string code = "tombstone-ttl-fixed";

        // expiresAt is FarFuture — remaining >> RefreshTokenLifetime
        await store.StoreAsync(code, BuildEntry(), CancellationToken.None);
        await store.TryRedeemAsync(code, "client-a", "family-b", CancellationToken.None);

        var tombstoneKey = BuildExpectedTombstoneKey(code);
        capturingCache.CapturedExpiries.Should().ContainKey(tombstoneKey,
            because: "tombstone must have been written to cache");
        capturingCache.CapturedExpiries[tombstoneKey].Should().Be(startTime + refreshTokenLifetime,
            because: "tombstone TTL must be exactly RefreshTokenLifetime even when remaining > RefreshTokenLifetime");
    }

    [Fact]
    public async Task TryRedeemAsync_tombstone_TTL_is_exactly_RefreshTokenLifetime()
    {
        var innerCache = new MemoryCache(new MemoryCacheOptions());
        var capturingCache = new CapturingMemoryCache(innerCache);

        var refreshTokenLifetime = TimeSpan.FromDays(14);
        var serverOptions = new AuthorizationServerOptions();
        serverOptions.TokenEndpoint.RefreshTokenLifetime = refreshTokenLifetime;

        var startTime = new DateTimeOffset(2090, 1, 1, 12, 0, 0, TimeSpan.Zero);
        var tp = new FakeTimeProvider(startTime);

        var store = CreateStore(cache: capturingCache, serverOptions: serverOptions, timeProvider: tp);
        const string code = "tombstone-min-ttl";

        await store.StoreAsync(code, BuildEntry(expiresAt: startTime.AddMinutes(5)), CancellationToken.None);
        await store.TryRedeemAsync(code, "client-a", "family-max", CancellationToken.None);

        var tombstoneKey = BuildExpectedTombstoneKey(code);
        capturingCache.CapturedExpiries.Should().ContainKey(tombstoneKey,
            because: "tombstone must have been written to the cache");
        capturingCache.CapturedExpiries[tombstoneKey].Should().Be(startTime + refreshTokenLifetime,
            because: "tombstone TTL must be exactly RefreshTokenLifetime");
    }

    [Fact]
    public async Task TryRedeemAsync_tombstone_TTL_is_exactly_RefreshTokenLifetime_using_capturing_cache()
    {
        // Arrange: use a capturing cache so we can inspect the AbsoluteExpiration set on the tombstone
        var innerCache = new MemoryCache(new MemoryCacheOptions());
        var capturingCache = new CapturingMemoryCache(innerCache);

        var refreshTokenLifetime = TimeSpan.FromDays(14);
        var serverOptions = new AuthorizationServerOptions();
        serverOptions.TokenEndpoint.RefreshTokenLifetime = refreshTokenLifetime;

        var startTime = new DateTimeOffset(2090, 1, 1, 12, 0, 0, TimeSpan.Zero);
        var tp = new FakeTimeProvider(startTime);

        var store = CreateStore(cache: capturingCache, serverOptions: serverOptions, timeProvider: tp);
        const string code = "tombstone-ttl-exact";

        await store.StoreAsync(code, BuildEntry(expiresAt: startTime.AddMinutes(5)), CancellationToken.None);
        await store.TryRedeemAsync(code, "client-a", "family-1", CancellationToken.None);

        var tombstoneKey = BuildExpectedTombstoneKey(code);
        capturingCache.CapturedExpiries.Should().ContainKey(tombstoneKey,
            because: "tombstone must have been written to the cache");

        var tombstoneExpiry = capturingCache.CapturedExpiries[tombstoneKey];
        tombstoneExpiry.Should().Be(startTime + refreshTokenLifetime,
            because: "tombstone TTL must be exactly RefreshTokenLifetime, not max(remaining, RefreshTokenLifetime)");
    }

    // ── AC 7 — Semaphore cleanup via post-eviction callback ───────────────────────────────────────

    [Fact]
    public async Task Semaphores_dictionary_entry_is_removed_when_cache_entry_is_explicitly_removed()
    {
        // Verify that when the cache entry is removed (e.g. by cache eviction),
        // the corresponding semaphore is also cleaned up.
        var cache = new MemoryCache(new MemoryCacheOptions());
        var store = CreateStore(cache: cache);
        const string code = "semaphore-cleanup-code";

        var semaphoresField = typeof(InMemoryAuthorizationCodeStore)
            .GetField("_semaphores", BindingFlags.NonPublic | BindingFlags.Instance)!;

        await store.StoreAsync(code, BuildEntry(), CancellationToken.None);

        var countAfterStore = (semaphoresField.GetValue(store) as System.Collections.ICollection)?.Count ?? -1;
        countAfterStore.Should().Be(1, because: "one semaphore should exist after storing one code");

        // Explicitly remove the entry from cache — this schedules the post-eviction callback
        var hashedKey = BuildExpectedEntryKey(code);
        cache.Remove(hashedKey);

        // MemoryCache fires post-eviction callbacks on a background ThreadPool thread.
        // Spin-wait deterministically rather than sleeping for a fixed interval.
        var semaphoresAfterRemoval = semaphoresField.GetValue(store) as System.Collections.ICollection;
        SpinWait.SpinUntil(() => semaphoresAfterRemoval?.Count == 0, TimeSpan.FromSeconds(2));

        semaphoresAfterRemoval?.Count.Should().Be(0,
            because: "the semaphore must be removed when the cache entry expires/is evicted");
    }

    [Fact]
    public async Task Semaphores_dictionary_does_not_grow_unboundedly_across_many_unique_codes()
    {
        var cache = new MemoryCache(new MemoryCacheOptions());
        var store = CreateStore(cache: cache);
        var semaphoresField = typeof(InMemoryAuthorizationCodeStore)
            .GetField("_semaphores", BindingFlags.NonPublic | BindingFlags.Instance)!;

        // Store 20 codes with far-future expiry
        for (int i = 0; i < 20; i++)
        {
            var code = $"growing-{i}";
            var entry = BuildEntry(expiresAt: FarFuture);
            await store.StoreAsync(code, entry, CancellationToken.None);
        }

        // Explicitly remove all entries to trigger post-eviction callbacks
        for (int i = 0; i < 20; i++)
        {
            var code = $"growing-{i}";
            var hashedKey = BuildExpectedEntryKey(code);
            cache.Remove(hashedKey);
        }

        // MemoryCache fires post-eviction callbacks on a background ThreadPool thread.
        // Spin-wait deterministically rather than sleeping for a fixed interval.
        var semaphoresCollection = semaphoresField.GetValue(store) as System.Collections.ICollection;
        SpinWait.SpinUntil(() => semaphoresCollection?.Count == 0, TimeSpan.FromSeconds(2));

        var countAfterCleanup = semaphoresCollection?.Count ?? -1;
        countAfterCleanup.Should().Be(0,
            because: "all semaphores should be removed after all cache entries are evicted");
    }

    // ── AC 8 — StoreKeyGenerator cryptographic strength ──────────────────────────────────────────

    [Fact]
    public void StoreKeyGenerator_generates_10000_distinct_keys()
    {
        var keys = Enumerable.Range(0, 10_000)
            .Select(_ => StoreKeyGenerator.Generate())
            .ToList();

        keys.Should().OnlyHaveUniqueItems(because: "no two store keys should collide in 10,000 samples");
    }

    [Fact]
    public void StoreKeyGenerator_keys_are_43_characters()
    {
        // Base64Url(32 bytes) = ceil(32 * 4 / 3) with no padding = 43 characters
        var keys = Enumerable.Range(0, 100).Select(_ => StoreKeyGenerator.Generate()).ToList();

        keys.Should().AllSatisfy(k => k.Length.Should().Be(43,
            because: "32 bytes Base64Url-encoded without padding produces exactly 43 characters"));
    }

    [Fact]
    public void StoreKeyGenerator_keys_contain_only_Base64Url_characters()
    {
        var validChars = new HashSet<char>("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_");

        var keys = Enumerable.Range(0, 100).Select(_ => StoreKeyGenerator.Generate()).ToList();

        keys.Should().AllSatisfy(k =>
            k.ToCharArray().Should().AllSatisfy(c =>
                validChars.Contains(c).Should().BeTrue(
                    because: $"Base64Url keys must only use URL-safe characters, but found '{c}'")));
    }

    [Fact]
    public void StoreKeyGenerator_is_in_ZeeKayDa_Auth_Stores_namespace()
    {
        typeof(StoreKeyGenerator).Namespace.Should().Be("ZeeKayDa.Auth.Stores");
    }

    // ── AC 9 — IMemoryCache failure wraps in ZeeKayDaStoreException ──────────────────────────────

    [Fact]
    public async Task StoreAsync_wraps_IMemoryCache_CreateEntry_exception_in_ZeeKayDaStoreException()
    {
        var faultingCache = new ThrowingMemoryCache();
        var store = CreateStore(cache: faultingCache);

        var act = async () =>
            await store.StoreAsync("any-code", BuildEntry(), CancellationToken.None);

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
            () => store.StoreAsync("code", BuildEntry(), CancellationToken.None));

        exception.Message.Should().NotBeNullOrWhiteSpace(
            because: "ZeeKayDaStoreException must carry a descriptive message");
    }

    [Fact]
    public async Task TryRedeemAsync_wraps_DataProtection_Protect_failure_in_ZeeKayDaStoreException()
    {
        // Arrange: use a DP provider that unprotects fine but throws on Protect
        var workingDp = new EphemeralDataProtectionProvider();
        var faultingDp = new ProtectFailingDataProtectionProvider(workingDp);

        // Store with the working DP so the entry is valid
        var cache = new MemoryCache(new MemoryCacheOptions());
        var storeForWrite = CreateStore(cache: cache, dp: workingDp);
        var storeForRedeem = CreateStore(cache: cache, dp: faultingDp);

        const string code = "dp-protect-failure-code";
        await storeForWrite.StoreAsync(code, BuildEntry(), CancellationToken.None);

        // Act: redeem using the faulting DP — Protect() will throw when writing tombstone
        var act = async () =>
            await storeForRedeem.TryRedeemAsync(code, "client-a", "family-1", CancellationToken.None);

        // Assert
        var assertion = await act.Should().ThrowAsync<ZeeKayDaStoreException>(
            because: "IDataProtector.Protect() failures during TryRedeemAsync must be wrapped in ZeeKayDaStoreException");
        assertion.Which.InnerException.Should().NotBeNull(
            because: "the original exception must be preserved as InnerException");
    }

    // ── AC 10 — Cross-purpose isolation ──────────────────────────────────────────────────────────

    [Fact]
    public void DataProtection_ciphertext_cannot_be_unprotected_under_different_purpose()
    {
        var dp = new EphemeralDataProtectionProvider();
        var authCodeProtector = dp.CreateProtector("ZeeKayDa.Auth:AuthorizationCodeStore");
        var refreshTokenProtector = dp.CreateProtector("ZeeKayDa.Auth:RefreshTokenStore");

        var plaintext = Encoding.UTF8.GetBytes("sensitive-authorization-code-data");
        var ciphertext = authCodeProtector.Protect(plaintext);

        var act = () => refreshTokenProtector.Unprotect(ciphertext);

        act.Should().Throw<CryptographicException>(
            because: "data protected under one purpose cannot be unprotected under a different purpose");
    }

    [Fact]
    public void DataProtection_protector_can_round_trip_under_same_purpose()
    {
        var dp = new EphemeralDataProtectionProvider();
        var protector = dp.CreateProtector("ZeeKayDa.Auth:AuthorizationCodeStore");

        var plaintext = Encoding.UTF8.GetBytes("authorization-code-payload");
        var ciphertext = protector.Protect(plaintext);
        var recovered = protector.Unprotect(ciphertext);

        recovered.Should().Equal(plaintext,
            because: "data protected and unprotected under the same purpose must round-trip");
    }

    // ── AC 11 — No ILogger constructor parameter ──────────────────────────────────────────────────

    [Fact]
    public void InMemoryAuthorizationCodeStore_constructor_has_no_ILogger_parameter()
    {
        var constructors = typeof(InMemoryAuthorizationCodeStore)
            .GetConstructors(BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Instance);

        var hasLoggerParam = constructors.Any(ctor =>
            ctor.GetParameters().Any(p =>
                p.ParameterType.IsGenericType
                    ? p.ParameterType.GetGenericTypeDefinition().FullName?.StartsWith("Microsoft.Extensions.Logging.ILogger") == true
                    : p.ParameterType.FullName?.StartsWith("Microsoft.Extensions.Logging.ILogger") == true));

        hasLoggerParam.Should().BeFalse(
            because: "InMemoryAuthorizationCodeStore must not accept ILogger to prevent sensitive values appearing in log sinks");
    }

    // ── AC 12 — XML documentation warning ────────────────────────────────────────────────────────

    [Fact]
    public void InMemoryAuthorizationCodeStore_XML_doc_contains_single_instance_deployment_invariant_warning()
    {
        var assemblyLocation = typeof(InMemoryAuthorizationCodeStore).Assembly.Location;
        var xmlDocPath = Path.ChangeExtension(assemblyLocation, ".xml");

        File.Exists(xmlDocPath).Should().BeTrue(
            because: $"XML doc file must exist at {xmlDocPath} for this verification to work");

        var doc = XDocument.Load(xmlDocPath);
        const string memberName = "T:ZeeKayDa.Auth.Stores.InMemoryAuthorizationCodeStore";

        var memberElement = doc.Descendants("member")
            .FirstOrDefault(m => m.Attribute("name")?.Value == memberName);

        memberElement.Should().NotBeNull(
            because: "the XML doc must contain an entry for InMemoryAuthorizationCodeStore");

        var fullText = memberElement!.Value;

        fullText.Should().Contain(
            "Single-instance is a deployment invariant, not a recommendation",
            because: "the XML documentation must warn operators that running multiple instances silently disables single-use enforcement");
    }

    // ── Additional security and correctness tests ─────────────────────────────────────────────────

    [Fact]
    public async Task TryRedeemAsync_returns_NotFound_for_unknown_code()
    {
        var store = CreateStore();

        var outcome = await store.TryRedeemAsync("never-stored", "client-a", "family-1", CancellationToken.None);

        outcome.Should().BeOfType<AuthorizationCodeRedemptionOutcome.NotFound>(
            because: "a code that was never stored must return NotFound");
    }

    [Fact]
    public async Task TryRedeemAsync_returns_AlreadyRedeemed_for_replay_after_successful_redemption()
    {
        var store = CreateStore();
        const string code = "replay-attack-code";

        await store.StoreAsync(code, BuildEntry(), CancellationToken.None);
        var firstOutcome = await store.TryRedeemAsync(code, "client-a", "family-original", CancellationToken.None);
        firstOutcome.Should().BeOfType<AuthorizationCodeRedemptionOutcome.Redeemed>();

        var replayOutcome = await store.TryRedeemAsync(code, "client-a", "family-replay", CancellationToken.None);

        replayOutcome.Should().BeOfType<AuthorizationCodeRedemptionOutcome.AlreadyRedeemed>(
            because: "a replayed code must return AlreadyRedeemed, not NotFound");
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

    [Fact]
    public async Task TryRedeemAsync_Redeemed_entry_matches_stored_entry()
    {
        var store = CreateStore();
        const string code = "round-trip-code";
        var now = DateTimeOffset.UtcNow;
        var entry = BuildEntry(
            clientId: "client-a",
            issuedAt: now,
            expiresAt: FarFuture);

        await store.StoreAsync(code, entry, CancellationToken.None);
        var outcome = await store.TryRedeemAsync(code, "client-a", "family-1", CancellationToken.None);

        outcome.Should().BeOfType<AuthorizationCodeRedemptionOutcome.Redeemed>()
            .Which.Entry.Should().BeEquivalentTo(entry,
            because: "the redeemed entry must match the stored entry exactly");
    }

    [Fact]
    public async Task StoreAsync_respects_CancellationToken()
    {
        var store = CreateStore();
        using var cts = new CancellationTokenSource();
        cts.Cancel();

        var act = async () =>
            await store.StoreAsync("code", BuildEntry(), cts.Token);

        await act.Should().ThrowAsync<OperationCanceledException>(
            because: "StoreAsync must honour a pre-cancelled CancellationToken");
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
    /// absolute expiration set on each cache entry via <c>Set&lt;TItem&gt;</c>.
    /// </summary>
    private sealed class CapturingMemoryCache : IMemoryCache
    {
        private readonly IMemoryCache _inner;
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

        internal void RecordExpiry(string key, DateTimeOffset? expiry) => CapturedExpiries[key] = expiry;

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
                    _cache.RecordExpiry(_key, value);
                }
            }
            public TimeSpan? AbsoluteExpirationRelativeToNow { get => _inner.AbsoluteExpirationRelativeToNow; set => _inner.AbsoluteExpirationRelativeToNow = value; }
            public TimeSpan? SlidingExpiration { get => _inner.SlidingExpiration; set => _inner.SlidingExpiration = value; }
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
