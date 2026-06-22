using System.Buffers.Text;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Options;

namespace ZeeKayDa.Auth.Stores;

/// <summary>
/// <see cref="IAuthorizationCodeStore"/> implementation backed by <see cref="IDistributedCache"/>.
/// Suitable for multi-instance deployments that share a distributed cache (e.g. Redis), but
/// <strong>not recommended for production</strong> use where atomic single-use enforcement is
/// required — see the atomicity note below.
/// </summary>
/// <remarks>
/// <para>
/// <strong>Cache key format.</strong> Entry keys are derived as
/// <c>zkd:code:{Base64Url(SHA-256(handle))}</c> and tombstone keys as
/// <c>zkd:code:{Base64Url(SHA-256(handle))}:redeemed</c>. Raw handles are never persisted as
/// keys or embedded in stored values. Entry and tombstone values are serialised to JSON and
/// encrypted using <see cref="IDataProtectionProvider"/>
/// (purpose: <c>ZeeKayDa.Auth:AuthorizationCodeStore</c>) before being written to the cache.
/// </para>
/// <para>
/// <strong>Non-atomic redemption (TOCTOU).</strong> Unlike <see cref="InMemoryAuthorizationCodeStore"/>,
/// this implementation does not hold a lock across the check-tombstone-write sequence. There is a
/// time-of-check-to-time-of-use (TOCTOU) window between reading the entry and writing the
/// tombstone in which two concurrent requests for the same code may both observe the entry as
/// valid. In the worst case, both redemptions succeed — violating the single-use requirement
/// of RFC 9700 §2.1.1. For production workloads that require strict single-use enforcement,
/// migrate to a store implementation backed by a transactional backend (see ADR 0008 §8).
/// </para>
/// <para>
/// <strong>Dev/test positioning.</strong> This store is suitable for development, testing, and
/// low-traffic single-process scenarios where the distributed cache is only accessed by one
/// server instance at a time. It must not be used in production deployments without understanding
/// and accepting the TOCTOU risk described above.
/// </para>
/// <para>
/// <strong>Data Protection.</strong> Operators MUST configure Data Protection key retention to
/// at least the configured refresh-token lifetime. Shorter retention causes live entries to
/// become unprotectable after key rotation, surfacing as
/// <see cref="AuthorizationCodeRedemptionOutcome.NotFound"/> at redemption time. Tombstone
/// decryption failures are treated as
/// <see cref="AuthorizationCodeRedemptionOutcome.AlreadyRedeemed"/> (with an empty family ID)
/// so replays are always rejected even when the family ID cannot be recovered.
/// </para>
/// <para>
/// <strong>Production migration.</strong> See ADR 0008 §8 for guidance on replacing this store
/// with one backed by a shared, atomic backend.
/// </para>
/// </remarks>
internal sealed class DistributedCacheAuthorizationCodeStore : IAuthorizationCodeStore
{
    private static readonly string DataProtectionPurpose = "ZeeKayDa.Auth:AuthorizationCodeStore";
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);

    private readonly IDistributedCache _cache;
    private readonly IDataProtector _protector;
    private readonly TimeSpan _refreshTokenLifetime;
    private readonly TimeProvider _timeProvider;
    private readonly TimeSpan _clockSkewTolerance;

    /// <summary>
    /// Initialises a new <see cref="DistributedCacheAuthorizationCodeStore"/>.
    /// </summary>
    /// <param name="cache">The distributed cache used to store entries and tombstones.</param>
    /// <param name="dataProtectionProvider">
    /// Provider used to create the data protector for encrypting stored values.
    /// </param>
    /// <param name="serverOptions">Server options providing the refresh token lifetime.</param>
    /// <param name="timeProvider">Time provider used for all UTC timestamp reads.</param>
    internal DistributedCacheAuthorizationCodeStore(
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
    public async Task StoreAsync(string code, AuthorizationCodeEntry entry, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(code);
        ArgumentNullException.ThrowIfNull(entry);
        cancellationToken.ThrowIfCancellationRequested();

        var hashedKey = ComputeHashedSegment(code);
        var entryKey = BuildEntryKey(hashedKey);

        try
        {
            var ttl = entry.ExpiresAt + _clockSkewTolerance - _timeProvider.GetUtcNow();
            if (ttl <= TimeSpan.Zero)
                throw new ZeeKayDaStoreException("Cannot store an already-expired authorization code entry.");

            var json = JsonSerializer.SerializeToUtf8Bytes(entry, JsonOptions);
            var protectedBytes = _protector.Protect(json);

            var cacheOptions = new DistributedCacheEntryOptions
            {
                AbsoluteExpirationRelativeToNow = ttl
            };

            await _cache.SetAsync(entryKey, protectedBytes, cacheOptions, cancellationToken).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is not (CryptographicException or JsonException or ZeeKayDaStoreException or OperationCanceledException))
        {
            throw new ZeeKayDaStoreException(
                "Failed to store the authorization code entry in the distributed cache.", ex);
        }
    }

    /// <inheritdoc/>
    public async ValueTask<AuthorizationCodeRedemptionOutcome> TryRedeemAsync(
        string code,
        string clientId,
        string familyId,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(code);
        ArgumentNullException.ThrowIfNull(clientId);
        ArgumentNullException.ThrowIfNull(familyId);
        cancellationToken.ThrowIfCancellationRequested();

        var hashedKey = ComputeHashedSegment(code);
        var entryKey = BuildEntryKey(hashedKey);
        var tombstoneKey = BuildTombstoneKey(hashedKey);

        // Check tombstone first — indicates a prior redemption (replay attack path).
        // TOCTOU note: there is no lock here; two concurrent requests may both pass this
        // check before either writes a tombstone. See type-level doc for full discussion.
        byte[]? tombstoneBytes;
        try
        {
            tombstoneBytes = await _cache.GetAsync(tombstoneKey, cancellationToken).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is not (ZeeKayDaStoreException or OperationCanceledException))
        {
            throw new ZeeKayDaStoreException(
                "Failed to read authorization code tombstone from the distributed cache.", ex);
        }

        if (tombstoneBytes is not null)
        {
            try
            {
                var tombstoneJson = _protector.Unprotect(tombstoneBytes);
                var tombstone = JsonSerializer.Deserialize<Tombstone>(tombstoneJson, JsonOptions)!;
                return new AuthorizationCodeRedemptionOutcome.AlreadyRedeemed { FamilyId = tombstone.FamilyId };
            }
            catch (Exception ex) when (ex is CryptographicException or JsonException)
            {
                _ = ex;
                // Tombstone exists but is unreadable — DP key rotated before tombstone TTL
                // expired, or serialised bytes are malformed. Cannot recover FamilyId but
                // the replay is still rejected.
                return new AuthorizationCodeRedemptionOutcome.AlreadyRedeemed { FamilyId = string.Empty };
            }
        }

        // Check entry exists.
        byte[]? entryBytes;
        try
        {
            entryBytes = await _cache.GetAsync(entryKey, cancellationToken).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is not (ZeeKayDaStoreException or OperationCanceledException))
        {
            throw new ZeeKayDaStoreException(
                "Failed to read authorization code entry from the distributed cache.", ex);
        }

        if (entryBytes is null)
            return new AuthorizationCodeRedemptionOutcome.NotFound();

        // Decrypt and deserialise entry.
        AuthorizationCodeEntry entry;
        try
        {
            var entryJson = _protector.Unprotect(entryBytes);
            entry = JsonSerializer.Deserialize<AuthorizationCodeEntry>(entryJson, JsonOptions)!;
        }
        catch (Exception ex) when (ex is CryptographicException or JsonException)
        {
            _ = ex;
            // Entry unreadable — DP key rotated before entry TTL, or malformed bytes.
            // Treat as NotFound per ADR 0008 §4b, §7.
            return new AuthorizationCodeRedemptionOutcome.NotFound();
        }

        // Logical expiry check against TimeProvider (cache may not have evicted yet).
        // ClockSkewTolerance provides a grace window for inter-node clock drift in
        // load-balanced deployments; see AuthorizationServerOptions.ClockSkewTolerance.
        var now = _timeProvider.GetUtcNow();
        if (now >= entry.ExpiresAt + _clockSkewTolerance)
            return new AuthorizationCodeRedemptionOutcome.NotFound();

        // Client binding — ClientMismatch does NOT consume the code.
        if (!string.Equals(entry.ClientId, clientId, StringComparison.Ordinal))
            return new AuthorizationCodeRedemptionOutcome.ClientMismatch();

        // Write tombstone then remove entry.
        // These two cache operations are not atomic — a crash between them leaves the entry
        // without a tombstone, allowing a second redemption. See type-level doc.
        var tombstoneTtl = _refreshTokenLifetime;
        var tombstoneOptions = new DistributedCacheEntryOptions
        {
            AbsoluteExpirationRelativeToNow = tombstoneTtl
        };

        var tombstoneValue = new Tombstone(familyId);
        try
        {
            var tombstoneJsonBytes = JsonSerializer.SerializeToUtf8Bytes(tombstoneValue, JsonOptions);
            var protectedTombstone = _protector.Protect(tombstoneJsonBytes);
            await _cache.SetAsync(tombstoneKey, protectedTombstone, tombstoneOptions, cancellationToken).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is not (CryptographicException or JsonException or ZeeKayDaStoreException or OperationCanceledException))
        {
            throw new ZeeKayDaStoreException(
                "Failed to write authorization code tombstone to the distributed cache.", ex);
        }

        try
        {
            await _cache.RemoveAsync(entryKey, cancellationToken).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is not (ZeeKayDaStoreException or OperationCanceledException))
        {
            throw new ZeeKayDaStoreException(
                "Failed to remove authorization code entry from the distributed cache.", ex);
        }

        return new AuthorizationCodeRedemptionOutcome.Redeemed { Entry = entry };
    }

    private static string ComputeHashedSegment(string handle)
    {
        var inputBytes = Encoding.UTF8.GetBytes(handle);
        var hash = SHA256.HashData(inputBytes);
        return Base64Url.EncodeToString(hash);
    }

    private static string BuildEntryKey(string hashedSegment) => $"zkd:code:{hashedSegment}";
    private static string BuildTombstoneKey(string hashedSegment) => $"zkd:code:{hashedSegment}:redeemed";

    private sealed record Tombstone(string FamilyId);
}
