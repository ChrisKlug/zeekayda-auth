using System.Buffers.Text;
using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.Caching.Memory;

namespace ZeeKayDa.Auth.Stores;

/// <summary>
/// Default <see cref="IRefreshTokenStore"/> implementation backed by
/// <see cref="IMemoryCache"/> with per-handle <see cref="SemaphoreSlim"/> atomicity.
/// </summary>
/// <remarks>
/// <para>
/// Cache keys are derived as <c>zkd:rt:{Base64Url(SHA-256(handle))}</c>. Both live entries
/// and tombstones share the same key — a tombstone replaces the live entry at the same cache
/// key when a token is consumed. Raw handles are never persisted as keys or embedded in stored
/// values. Entry and tombstone values are serialised to JSON and encrypted using
/// <see cref="IDataProtectionProvider"/> (purpose: <c>ZeeKayDa.Auth:RefreshTokenStore</c>)
/// before being written to the cache. The tombstone TTL equals the original entry's
/// <c>ExpiresAt</c> so the consumed marker lives exactly as long as the original token would
/// have.
/// </para>
/// <para>
/// <strong>Atomicity.</strong> <see cref="IRefreshTokenStore.TryConsumeAsync"/> holds a
/// per-handle <see cref="SemaphoreSlim"/> across the entire read-check-tombstone-write
/// sequence, ensuring that exactly one concurrent consumption attempt succeeds and all others
/// see <see cref="RefreshTokenConsumptionOutcome.AlreadyConsumed"/>.
/// </para>
/// <para>
/// <strong>Single-instance is a deployment invariant, not a recommendation.</strong>
/// Running multiple instances of this host with the in-memory default silently disables
/// single-use enforcement and refresh token reuse detection (RFC 9700 §4.14.2): tokens issued
/// by instance A are invisible to instance B. Multi-instance deployments MUST replace this
/// store with one backed by a shared, atomic backend (see ADR 0008 §8).
/// </para>
/// <para>
/// <strong>Data Protection.</strong> Operators MUST configure Data Protection key retention
/// to at least the configured refresh-token lifetime (ADR 0008 §4b, §7, §10). Both live
/// entries and consumed tombstones are stored under the same cache key
/// (<c>zkd:rt:{H(handle)}</c>) — this is the single-key design mandated by ADR 0008 §4a.
/// The <c>IsConsumed</c> discriminator that distinguishes a live entry from a tombstone lives
/// inside the encrypted payload; it is not visible until the payload is successfully decrypted.
/// Consequently, if a Data Protection key is rotated before tombstones have expired and the
/// payload becomes unreadable, <see cref="IRefreshTokenStore.TryConsumeAsync"/> returns
/// <see cref="RefreshTokenConsumptionOutcome.NotFound"/> — not
/// <see cref="RefreshTokenConsumptionOutcome.AlreadyConsumed"/> — because it cannot
/// distinguish an unreadable tombstone from an unreadable live entry. This behaviour is safe
/// <em>only</em> because ADR 0008 §4b, §7, and §10 require Data Protection key retention
/// to be at least <c>RefreshTokenLifetime</c>; shorter retention silently defeats replay
/// detection after key rotation. The single-key layout is a deliberate design choice per
/// ADR 0008 §4a, not an oversight.
/// </para>
/// <para>
/// <strong>Family revocation storage.</strong> Revoked family IDs are stored as plain hashed
/// string keys in a <see cref="ConcurrentDictionary{TKey,TValue}"/> rather than as
/// DP-encrypted cache entries. This is intentional: a Data Protection failure on a revocation
/// marker would fail open into "not revoked", silently re-enabling a compromised token family.
/// Storing the marker as a plain key ensures that revocation always takes effect regardless of
/// DP key availability.
/// </para>
/// </remarks>
internal sealed class InMemoryRefreshTokenStore : IRefreshTokenStore
{
    private static readonly string DataProtectionPurpose = "ZeeKayDa.Auth:RefreshTokenStore";
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);

    private readonly IMemoryCache _cache;
    private readonly IDataProtector _protector;
    private readonly TimeProvider _timeProvider;
    private readonly ConcurrentDictionary<string, SemaphoreSlim> _semaphores = new(StringComparer.Ordinal);
    private readonly ConcurrentDictionary<string, bool> _revokedFamilies = new(StringComparer.Ordinal);

    /// <summary>
    /// Initialises a new <see cref="InMemoryRefreshTokenStore"/>.
    /// </summary>
    /// <param name="cache">The memory cache used to store entries and tombstones.</param>
    /// <param name="dataProtectionProvider">
    /// Provider used to create the data protector for encrypting stored values.
    /// </param>
    /// <param name="timeProvider">Time provider used for all UTC timestamp reads.</param>
    internal InMemoryRefreshTokenStore(
        IMemoryCache cache,
        IDataProtectionProvider dataProtectionProvider,
        TimeProvider timeProvider)
    {
        ArgumentNullException.ThrowIfNull(cache);
        ArgumentNullException.ThrowIfNull(dataProtectionProvider);
        ArgumentNullException.ThrowIfNull(timeProvider);

        _cache = cache;
        _protector = dataProtectionProvider.CreateProtector(DataProtectionPurpose);
        _timeProvider = timeProvider;
    }

    /// <inheritdoc/>
    public Task StoreAsync(string tokenHandle, RefreshTokenEntry entry, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(tokenHandle);
        ArgumentNullException.ThrowIfNull(entry);

        cancellationToken.ThrowIfCancellationRequested();

        var hashedKey = ComputeHashedSegment(tokenHandle);
        var cacheKey = BuildCacheKey(hashedKey);

        var semaphore = _semaphores.GetOrAdd(hashedKey, _ => new SemaphoreSlim(1, 1));

        try
        {
            var payload = new CachePayload(false, entry, null);
            var json = JsonSerializer.SerializeToUtf8Bytes(payload, JsonOptions);
            var protectedBytes = _protector.Protect(json);

            using var cacheEntry = _cache.CreateEntry(cacheKey);
            cacheEntry.Value = protectedBytes;
            cacheEntry.AbsoluteExpiration = entry.ExpiresAt;
            cacheEntry.RegisterPostEvictionCallback(
                static (key, value, reason, state) =>
                {
                    var (semaphores, hKey) = ((ConcurrentDictionary<string, SemaphoreSlim>, string))state!;
                    // Remove the semaphore so it can be GC'd. Do NOT Dispose here — concurrent
                    // TryConsumeAsync callers may still be waiting on it and would get
                    // ObjectDisposedException. The semaphore is small and finalised without
                    // unmanaged resources; removing from the dictionary is sufficient to prevent
                    // unbounded growth.
                    semaphores.TryRemove(hKey, out _);
                },
                (_semaphores, hashedKey));
        }
        catch (Exception ex) when (ex is not ZeeKayDaStoreException)
        {
            throw new ZeeKayDaStoreException(
                "Failed to store the refresh token entry in the in-memory cache.", ex);
        }

        return Task.CompletedTask;
    }

    /// <inheritdoc/>
    public ValueTask<RefreshTokenEntry?> FindAsync(string tokenHandle, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(tokenHandle);

        cancellationToken.ThrowIfCancellationRequested();

        var hashedKey = ComputeHashedSegment(tokenHandle);
        var cacheKey = BuildCacheKey(hashedKey);

        if (!_cache.TryGetValue(cacheKey, out byte[]? protectedBytes))
            return ValueTask.FromResult<RefreshTokenEntry?>(null);

        CachePayload payload;
        try
        {
            var json = _protector.Unprotect(protectedBytes!);
            payload = JsonSerializer.Deserialize<CachePayload>(json, JsonOptions)!;
        }
        catch (Exception ex) when (ex is CryptographicException or JsonException)
        {
            _ = ex;
            return ValueTask.FromResult<RefreshTokenEntry?>(null);
        }

        if (payload.IsConsumed)
            return ValueTask.FromResult<RefreshTokenEntry?>(null);

        if (_timeProvider.GetUtcNow() >= payload.Entry!.ExpiresAt)
            return ValueTask.FromResult<RefreshTokenEntry?>(null);

        if (_revokedFamilies.ContainsKey(ComputeHashedSegment(payload.Entry.FamilyId)))
            return ValueTask.FromResult<RefreshTokenEntry?>(null);

        return ValueTask.FromResult<RefreshTokenEntry?>(payload.Entry);
    }

    /// <inheritdoc/>
    public async ValueTask<RefreshTokenConsumptionOutcome> TryConsumeAsync(
        string tokenHandle,
        string clientId,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(tokenHandle);
        ArgumentNullException.ThrowIfNull(clientId);

        var hashedKey = ComputeHashedSegment(tokenHandle);
        var cacheKey = BuildCacheKey(hashedKey);

        var semaphore = _semaphores.GetOrAdd(hashedKey, _ => new SemaphoreSlim(1, 1));
        var consumed = false;

        await semaphore.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            if (!_cache.TryGetValue(cacheKey, out byte[]? protectedBytes))
                return new RefreshTokenConsumptionOutcome.NotFound();

            CachePayload payload;
            try
            {
                var json = _protector.Unprotect(protectedBytes!);
                payload = JsonSerializer.Deserialize<CachePayload>(json, JsonOptions)!;
            }
            catch (Exception ex) when (ex is CryptographicException or JsonException)
            {
                _ = ex;
                return new RefreshTokenConsumptionOutcome.NotFound();
            }

            if (payload.IsConsumed)
                return new RefreshTokenConsumptionOutcome.AlreadyConsumed { FamilyId = payload.FamilyId! };

            if (_timeProvider.GetUtcNow() >= payload.Entry!.ExpiresAt)
                return new RefreshTokenConsumptionOutcome.NotFound();

            if (_revokedFamilies.ContainsKey(ComputeHashedSegment(payload.Entry.FamilyId)))
                return new RefreshTokenConsumptionOutcome.Revoked { FamilyId = payload.Entry.FamilyId };

            if (!string.Equals(payload.Entry.ClientId, clientId, StringComparison.Ordinal))
                return new RefreshTokenConsumptionOutcome.ClientMismatch();

            try
            {
                var tombstone = new CachePayload(true, null, payload.Entry.FamilyId);
                var tombstoneJson = JsonSerializer.SerializeToUtf8Bytes(tombstone, JsonOptions);
                var protectedTombstone = _protector.Protect(tombstoneJson);
                _cache.Set(cacheKey, protectedTombstone, payload.Entry.ExpiresAt);
            }
            catch (Exception ex) when (ex is not ZeeKayDaStoreException)
            {
                throw new ZeeKayDaStoreException("Failed to write consumed tombstone to cache.", ex);
            }

            consumed = true;
            return new RefreshTokenConsumptionOutcome.Consumed { Entry = payload.Entry };
        }
        finally
        {
            semaphore.Release();
            if (consumed)
                _semaphores.TryRemove(KeyValuePair.Create(hashedKey, semaphore));
        }
    }

    /// <inheritdoc/>
    public Task RevokeFamilyAsync(string familyId, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(familyId);

        cancellationToken.ThrowIfCancellationRequested();

        _revokedFamilies.TryAdd(ComputeHashedSegment(familyId), true);

        return Task.CompletedTask;
    }

    private static string ComputeHashedSegment(string handle)
    {
        var inputBytes = Encoding.UTF8.GetBytes(handle);
        var hash = SHA256.HashData(inputBytes);
        return Base64Url.EncodeToString(hash);
    }

    private static string BuildCacheKey(string hashedSegment) => $"zkd:rt:{hashedSegment}";

    private sealed record CachePayload(bool IsConsumed, RefreshTokenEntry? Entry, string? FamilyId);
}
