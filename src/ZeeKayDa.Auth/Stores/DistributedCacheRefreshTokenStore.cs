using System.Buffers.Text;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Options;

namespace ZeeKayDa.Auth.Stores;

/// <summary>
/// <see cref="IRefreshTokenStore"/> implementation backed by <see cref="IDistributedCache"/>.
/// Suitable for multi-instance deployments that share a distributed cache (e.g. Redis), but
/// <strong>not recommended for production</strong> use where atomic single-use enforcement is
/// required — see the atomicity note below.
/// </summary>
/// <remarks>
/// <para>
/// <strong>Cache key format.</strong> Entry and tombstone keys are derived as
/// <c>zkd:rt:{Base64Url(SHA-256(handle))}</c>. Both a live entry and its consumed tombstone
/// share the same key — a tombstone replaces the live entry in place when a token is consumed.
/// Family revocation marker keys are derived as
/// <c>zkd:rt:family:{Base64Url(SHA-256(familyId))}:revoked</c>. Raw handles and family IDs are
/// never persisted as keys or embedded in stored values. Entry and tombstone values are serialised
/// to JSON and encrypted using <see cref="IDataProtectionProvider"/>
/// (purpose: <c>ZeeKayDa.Auth:RefreshTokenStore</c>) before being written to the cache.
/// </para>
/// <para>
/// <strong>Non-atomic consumption and revocation check (TOCTOU).</strong> Unlike
/// <see cref="InMemoryRefreshTokenStore"/>, this implementation does not hold a lock across
/// the read-check-write sequence. There is a time-of-check-to-time-of-use (TOCTOU) window
/// between reading the entry and writing the consumed tombstone in which two concurrent requests
/// for the same token may both observe the entry as valid. In the worst case, both consume
/// calls succeed, violating the single-use requirement of RFC 9700 §4.14.2. For production
/// workloads that require strict single-use enforcement, migrate to a store implementation
/// backed by a transactional backend (see ADR 0008 §8).
/// </para>
/// <para>
/// <strong>Dev/test positioning.</strong> This store is suitable for development, testing, and
/// low-traffic single-process scenarios where the distributed cache is only accessed by one
/// server instance at a time. It must not be used in production deployments without understanding
/// and accepting the TOCTOU risk described above.
/// </para>
/// <para>
/// <strong>Family revocation markers are plaintext (fail-safe design).</strong> When a token
/// family is revoked, a plaintext sentinel byte is written to the cache at the revocation marker
/// key. The marker is intentionally not DP-encrypted: a Data Protection failure on a revocation
/// marker would fail open into "not revoked", silently re-enabling a compromised token family.
/// Plaintext markers ensure revocation takes effect regardless of DP key availability.
/// Family revocation markers are retained for <c>RefreshTokenLifetime + 5 minutes</c>,
/// ensuring they outlive all tokens in the family by a small grace margin.
/// </para>
/// <para>
/// <strong>Data Protection.</strong> Operators MUST configure Data Protection key retention to
/// at least the configured refresh-token lifetime (ADR 0008 §4b, §7, §10). If a Data Protection
/// key is rotated before a tombstone has expired and the payload becomes unreadable,
/// <see cref="IRefreshTokenStore.TryConsumeAsync"/> returns
/// <see cref="RefreshTokenConsumptionOutcome.NotFound"/> rather than
/// <see cref="RefreshTokenConsumptionOutcome.AlreadyConsumed"/> — because it cannot distinguish
/// an unreadable tombstone from an unreadable live entry. This behaviour is safe only with the
/// required key retention in place.
/// </para>
/// <para>
/// <strong>Production migration.</strong> See ADR 0008 §8 for guidance on replacing this store
/// with one backed by a shared, atomic backend.
/// </para>
/// </remarks>
internal sealed class DistributedCacheRefreshTokenStore : IRefreshTokenStore
{
    private static readonly string DataProtectionPurpose = "ZeeKayDa.Auth:RefreshTokenStore";
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);
    private static readonly byte[] RevocationSentinel = [1];

    private readonly IDistributedCache _cache;
    private readonly IDataProtector _protector;
    private readonly TimeSpan _refreshTokenLifetime;
    private readonly TimeProvider _timeProvider;
    private readonly TimeSpan _clockSkewTolerance;

    /// <summary>
    /// Initialises a new <see cref="DistributedCacheRefreshTokenStore"/>.
    /// </summary>
    /// <param name="cache">The distributed cache used to store entries, tombstones, and revocation markers.</param>
    /// <param name="dataProtectionProvider">
    /// Provider used to create the data protector for encrypting stored entry and tombstone values.
    /// </param>
    /// <param name="serverOptions">Server options providing the refresh token lifetime.</param>
    /// <param name="timeProvider">Time provider used for all UTC timestamp reads.</param>
    internal DistributedCacheRefreshTokenStore(
        IDistributedCache cache,
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
        _refreshTokenLifetime = serverOptions.Value.TokenEndpoint.RefreshTokenLifetime;
        _timeProvider = timeProvider;
        _clockSkewTolerance = serverOptions.Value.ClockSkewTolerance;
    }

    /// <inheritdoc/>
    public async Task StoreAsync(string tokenHandle, RefreshTokenEntry entry, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(tokenHandle);
        ArgumentNullException.ThrowIfNull(entry);
        cancellationToken.ThrowIfCancellationRequested();

        var hashedKey = ComputeHashedSegment(tokenHandle);
        var cacheKey = BuildCacheKey(hashedKey);

        try
        {
            var ttl = entry.ExpiresAt - _timeProvider.GetUtcNow();
            if (ttl <= TimeSpan.Zero)
                throw new ZeeKayDaStoreException("Cannot store an already-expired refresh token entry.");

            var payload = new CachePayload(false, entry, null);
            var json = JsonSerializer.SerializeToUtf8Bytes(payload, JsonOptions);
            var protectedBytes = _protector.Protect(json);

            var cacheOptions = new DistributedCacheEntryOptions
            {
                AbsoluteExpirationRelativeToNow = ttl
            };

            await _cache.SetAsync(cacheKey, protectedBytes, cacheOptions, cancellationToken).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is not (CryptographicException or JsonException or ZeeKayDaStoreException or OperationCanceledException))
        {
            throw new ZeeKayDaStoreException(
                "Failed to store the refresh token entry in the distributed cache.", ex);
        }
    }

    /// <inheritdoc/>
    public async ValueTask<RefreshTokenEntry?> FindAsync(string tokenHandle, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(tokenHandle);
        cancellationToken.ThrowIfCancellationRequested();

        var hashedKey = ComputeHashedSegment(tokenHandle);
        var cacheKey = BuildCacheKey(hashedKey);

        byte[]? protectedBytes;
        try
        {
            protectedBytes = await _cache.GetAsync(cacheKey, cancellationToken).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is not (ZeeKayDaStoreException or OperationCanceledException))
        {
            throw new ZeeKayDaStoreException(
                "Failed to read refresh token entry from the distributed cache.", ex);
        }

        if (protectedBytes is null)
            return null;

        CachePayload payload;
        try
        {
            var json = _protector.Unprotect(protectedBytes);
            payload = JsonSerializer.Deserialize<CachePayload>(json, JsonOptions)!;
        }
        catch (Exception ex) when (ex is CryptographicException or JsonException)
        {
            _ = ex;
            return null;
        }

        if (payload.IsConsumed)
            return null;

        if (_timeProvider.GetUtcNow() >= payload.Entry!.ExpiresAt + _clockSkewTolerance)
            return null;

        var markerKey = BuildRevocationMarkerKey(ComputeHashedSegment(payload.Entry.FamilyId));

        byte[]? markerBytes;
        try
        {
            markerBytes = await _cache.GetAsync(markerKey, cancellationToken).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is not (ZeeKayDaStoreException or OperationCanceledException))
        {
            throw new ZeeKayDaStoreException(
                "Failed to read family revocation marker from the distributed cache.", ex);
        }

        if (markerBytes is not null)
            return null;

        return payload.Entry;
    }

    /// <inheritdoc/>
    public async ValueTask<RefreshTokenConsumptionOutcome> TryConsumeAsync(
        string tokenHandle,
        string clientId,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(tokenHandle);
        ArgumentNullException.ThrowIfNull(clientId);
        cancellationToken.ThrowIfCancellationRequested();

        var hashedKey = ComputeHashedSegment(tokenHandle);
        var cacheKey = BuildCacheKey(hashedKey);

        // TOCTOU note: there is no lock here; two concurrent requests may both pass the
        // consumed-check before either writes the tombstone. See type-level doc.
        byte[]? protectedBytes;
        try
        {
            protectedBytes = await _cache.GetAsync(cacheKey, cancellationToken).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is not (ZeeKayDaStoreException or OperationCanceledException))
        {
            throw new ZeeKayDaStoreException(
                "Failed to read refresh token entry from the distributed cache.", ex);
        }

        if (protectedBytes is null)
            return new RefreshTokenConsumptionOutcome.NotFound();

        CachePayload payload;
        try
        {
            var json = _protector.Unprotect(protectedBytes);
            payload = JsonSerializer.Deserialize<CachePayload>(json, JsonOptions)!;
        }
        catch (Exception ex) when (ex is CryptographicException or JsonException)
        {
            _ = ex;
            return new RefreshTokenConsumptionOutcome.NotFound();
        }

        if (payload.IsConsumed)
            return new RefreshTokenConsumptionOutcome.AlreadyConsumed { FamilyId = payload.FamilyId! };

        if (_timeProvider.GetUtcNow() >= payload.Entry!.ExpiresAt + _clockSkewTolerance)
            return new RefreshTokenConsumptionOutcome.NotFound();

        var markerKey = BuildRevocationMarkerKey(ComputeHashedSegment(payload.Entry.FamilyId));

        byte[]? markerBytes;
        try
        {
            markerBytes = await _cache.GetAsync(markerKey, cancellationToken).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is not (ZeeKayDaStoreException or OperationCanceledException))
        {
            throw new ZeeKayDaStoreException(
                "Failed to read family revocation marker from the distributed cache.", ex);
        }

        if (markerBytes is not null)
            return new RefreshTokenConsumptionOutcome.Revoked { FamilyId = payload.Entry.FamilyId };

        if (!string.Equals(payload.Entry.ClientId, clientId, StringComparison.Ordinal))
            return new RefreshTokenConsumptionOutcome.ClientMismatch();

        // Write the consumed tombstone at the same cache key.
        // The two cache operations (write tombstone, which implicitly replaces the live entry
        // at the same key) are not split across separate keys — the single-key layout from
        // ADR 0008 §4a means SetAsync overwrites the live entry in place.
        try
        {
            var tombstone = new CachePayload(true, null, payload.Entry.FamilyId);
            var tombstoneJson = JsonSerializer.SerializeToUtf8Bytes(tombstone, JsonOptions);
            var protectedTombstone = _protector.Protect(tombstoneJson);

            var cacheOptions = new DistributedCacheEntryOptions
            {
                AbsoluteExpirationRelativeToNow = _refreshTokenLifetime
            };

            await _cache.SetAsync(cacheKey, protectedTombstone, cacheOptions, cancellationToken).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is not (CryptographicException or JsonException or ZeeKayDaStoreException or OperationCanceledException))
        {
            throw new ZeeKayDaStoreException(
                "Failed to write consumed refresh token tombstone to the distributed cache.", ex);
        }

        return new RefreshTokenConsumptionOutcome.Consumed { Entry = payload.Entry };
    }

    /// <inheritdoc/>
    public async Task RevokeFamilyAsync(string familyId, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(familyId);
        cancellationToken.ThrowIfCancellationRequested();

        var markerKey = BuildRevocationMarkerKey(ComputeHashedSegment(familyId));
        var markerTtl = _refreshTokenLifetime + TimeSpan.FromMinutes(5);
        var markerOptions = new DistributedCacheEntryOptions
        {
            AbsoluteExpirationRelativeToNow = markerTtl
        };

        try
        {
            await _cache.SetAsync(markerKey, RevocationSentinel, markerOptions, cancellationToken).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is not (ZeeKayDaStoreException or OperationCanceledException))
        {
            throw new ZeeKayDaStoreException(
                "Failed to write family revocation marker to the distributed cache.", ex);
        }
    }

    private static string ComputeHashedSegment(string handle)
    {
        var inputBytes = Encoding.UTF8.GetBytes(handle);
        var hash = SHA256.HashData(inputBytes);
        return Base64Url.EncodeToString(hash);
    }

    private static string BuildCacheKey(string hashedSegment) => $"zkd:rt:{hashedSegment}";
    private static string BuildRevocationMarkerKey(string hashedSegment) => $"zkd:rt:family:{hashedSegment}:revoked";

    private sealed record CachePayload(bool IsConsumed, RefreshTokenEntry? Entry, string? FamilyId);
}
