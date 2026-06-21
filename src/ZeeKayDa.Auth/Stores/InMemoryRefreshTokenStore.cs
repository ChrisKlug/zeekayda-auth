using System.Buffers.Text;
using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Options;

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
/// to at least the configured refresh-token lifetime. Shorter retention causes live entries
/// to become unprotectable after key rotation, surfacing as
/// <see cref="RefreshTokenConsumptionOutcome.NotFound"/> at consumption time. Tombstone
/// decryption failures are treated as
/// <see cref="RefreshTokenConsumptionOutcome.AlreadyConsumed"/> so replays are always rejected
/// even when the family ID cannot be recovered.
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
    /// <param name="serverOptions">
    /// Server options accepted to match DI registration patterns; not used by this
    /// implementation (tombstone TTL is derived from the entry's <c>ExpiresAt</c>).
    /// </param>
    /// <param name="timeProvider">Time provider used for all UTC timestamp reads.</param>
    internal InMemoryRefreshTokenStore(
        IMemoryCache cache,
        IDataProtectionProvider dataProtectionProvider,
        IOptions<AuthorizationServerOptions> serverOptions,
        TimeProvider timeProvider)
    {
        ArgumentNullException.ThrowIfNull(cache);
        ArgumentNullException.ThrowIfNull(dataProtectionProvider);
        ArgumentNullException.ThrowIfNull(serverOptions);
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

        try
        {
            var payload = new CachePayload(false, entry, null);
            var json = JsonSerializer.SerializeToUtf8Bytes(payload, JsonOptions);
            var protectedBytes = _protector.Protect(json);

            using var cacheEntry = _cache.CreateEntry(cacheKey);
            cacheEntry.Value = protectedBytes;
            cacheEntry.AbsoluteExpiration = entry.ExpiresAt;
        }
        catch (Exception ex) when (ex is not ZeeKayDaStoreException)
        {
            throw new ZeeKayDaStoreException(
                "Failed to store the refresh token entry in the in-memory cache.", ex);
        }

        _semaphores.GetOrAdd(hashedKey, _ => new SemaphoreSlim(1, 1));

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
