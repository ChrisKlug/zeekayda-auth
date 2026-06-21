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
/// Default <see cref="IAuthorizationCodeStore"/> implementation backed by
/// <see cref="IMemoryCache"/> with per-handle <see cref="SemaphoreSlim"/> atomicity.
/// </summary>
/// <remarks>
/// <para>
/// Cache keys are derived as <c>zkd:code:{Base64Url(SHA-256(handle))}</c> for unredeemed
/// entries and <c>zkd:code:{Base64Url(SHA-256(handle))}:redeemed</c> for tombstones. Raw
/// handles are never persisted as keys or embedded in stored values. Entry and tombstone
/// values are serialised to JSON and encrypted using
/// <see cref="IDataProtectionProvider"/> (purpose: <c>ZeeKayDa.Auth:AuthorizationCodeStore</c>)
/// before being written to the cache.
/// </para>
/// <para>
/// <strong>Atomicity.</strong> <see cref="IAuthorizationCodeStore.TryRedeemAsync"/> holds a
/// per-handle <see cref="SemaphoreSlim"/> across the entire read-check-tombstone-write
/// sequence, ensuring that exactly one concurrent redemption attempt succeeds and all others
/// see <see cref="AuthorizationCodeRedemptionOutcome.AlreadyRedeemed"/>.
/// </para>
/// <para>
/// <strong>Single-instance is a deployment invariant, not a recommendation.</strong>
/// Running multiple instances of this host with the in-memory default silently disables
/// single-use enforcement (RFC 9700 §2.1.1) and refresh token reuse detection
/// (RFC 9700 §4.14.2): codes and refresh tokens issued by instance A are invisible to
/// instance B. Multi-instance deployments MUST replace this store with one backed by a
/// shared, atomic backend (see ADR 0008 §8).
/// </para>
/// <para>
/// <strong>Data Protection.</strong> Operators MUST configure Data Protection key retention
/// to at least the configured refresh-token lifetime. Shorter retention causes live entries
/// to become unprotectable after key rotation, surfacing as
/// <see cref="AuthorizationCodeRedemptionOutcome.NotFound"/> at redemption time. Tombstone
/// decryption failures are treated as
/// <see cref="AuthorizationCodeRedemptionOutcome.AlreadyRedeemed"/> (with an empty family
/// ID) so replays are always rejected even when the family ID cannot be recovered.
/// </para>
/// </remarks>
internal sealed class InMemoryAuthorizationCodeStore : IAuthorizationCodeStore
{
    private static readonly string DataProtectionPurpose = "ZeeKayDa.Auth:AuthorizationCodeStore";
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);

    private readonly IMemoryCache _cache;
    private readonly IDataProtector _protector;
    private readonly TimeSpan _refreshTokenLifetime;
    private readonly TimeProvider _timeProvider;
    private readonly ConcurrentDictionary<string, SemaphoreSlim> _semaphores = new(StringComparer.Ordinal);

    /// <summary>
    /// Initialises a new <see cref="InMemoryAuthorizationCodeStore"/>.
    /// </summary>
    /// <param name="cache">The memory cache used to store entries and tombstones.</param>
    /// <param name="dataProtectionProvider">
    /// Provider used to create the data protector for encrypting stored values.
    /// </param>
    /// <param name="serverOptions">Server options providing the refresh token lifetime.</param>
    /// <param name="timeProvider">Time provider used for all UTC timestamp reads.</param>
    public InMemoryAuthorizationCodeStore(
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
        _refreshTokenLifetime = serverOptions.Value.TokenEndpoint.RefreshTokenLifetime;
        _timeProvider = timeProvider;
    }

    /// <inheritdoc/>
    public Task StoreAsync(string code, AuthorizationCodeEntry entry, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(code);
        ArgumentNullException.ThrowIfNull(entry);

        cancellationToken.ThrowIfCancellationRequested();

        var hashedKey = ComputeHashedSegment(code);
        var entryKey = BuildEntryKey(hashedKey);

        try
        {
            var json = JsonSerializer.SerializeToUtf8Bytes(entry, JsonOptions);
            var protectedBytes = _protector.Protect(json);

            using var cacheEntry = _cache.CreateEntry(entryKey);
            cacheEntry.Value = protectedBytes;
            cacheEntry.AbsoluteExpiration = entry.ExpiresAt;
        }
        catch (Exception ex) when (ex is not ZeeKayDaStoreException)
        {
            throw new ZeeKayDaStoreException(
                "Failed to store the authorization code entry in the in-memory cache.", ex);
        }

        _semaphores.GetOrAdd(hashedKey, _ => new SemaphoreSlim(1, 1));

        return Task.CompletedTask;
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

        var hashedKey = ComputeHashedSegment(code);
        var entryKey = BuildEntryKey(hashedKey);
        var tombstoneKey = BuildTombstoneKey(hashedKey);

        var semaphore = _semaphores.GetOrAdd(hashedKey, _ => new SemaphoreSlim(1, 1));
        var redeemed = false;
        await semaphore.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            // Check tombstone first — indicates a prior redemption (replay attack path)
            if (_cache.TryGetValue(tombstoneKey, out byte[]? tombstoneBytes))
            {
                try
                {
                    var tombstoneJson = _protector.Unprotect(tombstoneBytes!);
                    var tombstone = JsonSerializer.Deserialize<Tombstone>(tombstoneJson, JsonOptions)!;
                    return new AuthorizationCodeRedemptionOutcome.AlreadyRedeemed { FamilyId = tombstone.FamilyId };
                }
                catch (Exception ex) when (ex is CryptographicException or JsonException)
                {
                    // Tombstone exists but is unreadable — either DP key was rotated before RefreshTokenLifetime
                    // (CryptographicException) or the decrypted bytes are malformed JSON (JsonException).
                    // Cannot recover FamilyId — family revocation is a no-op, but the replay is still rejected.
                    return new AuthorizationCodeRedemptionOutcome.AlreadyRedeemed { FamilyId = string.Empty };
                }
            }

            // Check entry exists
            if (!_cache.TryGetValue(entryKey, out byte[]? entryBytes))
                return new AuthorizationCodeRedemptionOutcome.NotFound();

            // Decrypt entry
            AuthorizationCodeEntry entry;
            try
            {
                var entryJson = _protector.Unprotect(entryBytes!);
                entry = JsonSerializer.Deserialize<AuthorizationCodeEntry>(entryJson, JsonOptions)!;
            }
            catch (Exception ex) when (ex is CryptographicException or JsonException)
            {
                // Entry exists but is unreadable — either DP key was rotated before RefreshTokenLifetime
                // (CryptographicException) or the decrypted bytes are malformed JSON (JsonException).
                // Treat as NotFound per ADR 0008 §4b, §7.
                return new AuthorizationCodeRedemptionOutcome.NotFound();
            }

            // Check logical expiry against TimeProvider (cache may not have evicted yet)
            var now = _timeProvider.GetUtcNow();
            if (now >= entry.ExpiresAt)
                return new AuthorizationCodeRedemptionOutcome.NotFound();

            // Check client binding — ClientMismatch does NOT consume the code (AC 5)
            if (!string.Equals(entry.ClientId, clientId, StringComparison.Ordinal))
                return new AuthorizationCodeRedemptionOutcome.ClientMismatch();

            // Write tombstone atomically with entry removal
            var tombstoneExpiry = now + _refreshTokenLifetime;

            try
            {
                var tombstoneValue = new Tombstone(familyId, tombstoneExpiry);
                var tombstoneJsonBytes = JsonSerializer.SerializeToUtf8Bytes(tombstoneValue, JsonOptions);
                var protectedTombstone = _protector.Protect(tombstoneJsonBytes);

                _cache.Set(tombstoneKey, protectedTombstone, tombstoneExpiry);
                _cache.Remove(entryKey);
            }
            catch (Exception ex) when (ex is not ZeeKayDaStoreException)
            {
                throw new ZeeKayDaStoreException(
                    "Failed to write tombstone or remove authorization code entry from cache.", ex);
            }

            redeemed = true;
            return new AuthorizationCodeRedemptionOutcome.Redeemed { Entry = entry };
        }
        finally
        {
            semaphore.Release();
            if (redeemed)
                _semaphores.TryRemove(KeyValuePair.Create(hashedKey, semaphore));
        }
    }

    private static string ComputeHashedSegment(string handle)
    {
        var inputBytes = Encoding.UTF8.GetBytes(handle);
        var hash = SHA256.HashData(inputBytes);
        return Base64Url.EncodeToString(hash);
    }

    private static string BuildEntryKey(string hashedSegment) => $"zkd:code:{hashedSegment}";
    private static string BuildTombstoneKey(string hashedSegment) => $"zkd:code:{hashedSegment}:redeemed";

    private sealed record Tombstone(string FamilyId, DateTimeOffset ExpiresAt);
}
