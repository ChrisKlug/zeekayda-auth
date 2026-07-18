using System.Text.Json;
using Microsoft.Extensions.Caching.Distributed;

namespace ZeeKayDa.Auth.Stores;

/// <summary>
/// <see cref="IRefreshTokenGrantStore"/> implementation backed by <see cref="IDistributedCache"/>.
/// Suitable for multi-instance dev/test deployments that share a distributed cache (e.g. Redis),
/// but <strong>not recommended for production</strong> use where atomic single-use enforcement and
/// complete revocation are required — see the caveats below.
/// </summary>
/// <remarks>
/// <para>
/// <strong>This is NOT the "framework-owned Redis adapter that owns the secondary-index maintenance
/// correctly, once" ADR 0014 §8 anticipates as the sanctioned production path for a non-queryable
/// backend.</strong> <see cref="IDistributedCache"/> has no atomic multi-key primitive (no
/// transactional read-modify-write, no native compare-and-set across a grant row and its indexes),
/// so this adapter cannot structurally close the TOCTOU/index-drift gap §8 describes — it can only
/// document it, which the remarks below do. A correct, production-grade Redis adapter (Lua scripting
/// or hash-tagged <c>WATCH-MULTI-EXEC</c>) remains unbuilt; the sanctioned production path today is a
/// natively queryable backend (relational SQL or Cosmos) implementing <see cref="IRefreshTokenGrantStore"/>
/// directly. Treat this class as the dev/test convenience slot only.
/// </para>
/// <para>
/// <strong>Not a queryable backend (ADR 0014 §8).</strong> <see cref="IDistributedCache"/> has no
/// native <c>WHERE</c>, so this store maintains its own secondary indexes — a
/// <c>zkd:rtg:family:{familyId}</c> entry and a <c>zkd:rtg:subject:{subject}</c> entry, each a
/// JSON <see cref="RefreshTokenGrantIndexEnvelope"/> listing the handle-hash keys that belong to
/// that family/subject — so that <see cref="RevokeFamilyAsync"/> and
/// <see cref="RevokeBySubjectAsync"/> can locate every grant to revoke. This is exactly the
/// framework-owned index-maintenance burden ADR 0014 §8 says a hand-rolled Redis backend must
/// not be left to a newcomer to re-derive.
/// </para>
/// <para>
/// <strong>Non-atomic consumption and index maintenance (TOCTOU, dev/test only).</strong> Neither
/// the grant write nor the index update is transactional with the other, and
/// <see cref="TryMarkConsumedAsync"/> is a read-then-write, not a native compare-and-set. Two
/// concurrent requests for the same handle may both observe the grant as
/// <see cref="RefreshGrantStatus.Active"/> before either writes
/// <see cref="RefreshGrantStatus.Consumed"/>, and a crash between a grant insert and its index
/// update can leave an <see cref="RefreshGrantStatus.Active"/> grant that a subsequent
/// <see cref="RevokeFamilyAsync"/>/<see cref="RevokeBySubjectAsync"/> call cannot find via the
/// index — the exact drift ADR 0014 §8 warns a non-transactional dual-write produces. This store
/// is positioned for development, testing, and low-traffic single-process scenarios only. For
/// production, use a natively queryable backend (relational SQL or Cosmos) implementing
/// <see cref="IRefreshTokenGrantStore"/> directly.
/// </para>
/// <para>
/// <strong>Self-clean via TTL.</strong> Grant rows and index entries are stored with an absolute
/// cache expiration derived from <see cref="RefreshTokenGrant.FamilyAbsoluteExpiry"/>, so they
/// self-evict once the whole family's absolute cap has passed, without a separate sweep job.
/// </para>
/// </remarks>
internal sealed class DistributedCacheRefreshTokenGrantStore : IRefreshTokenGrantStore
{
    private readonly IDistributedCache _cache;

    /// <summary>Initialises a new <see cref="DistributedCacheRefreshTokenGrantStore"/>.</summary>
    /// <param name="cache">The distributed cache used to store grants and secondary indexes.</param>
    public DistributedCacheRefreshTokenGrantStore(IDistributedCache cache)
    {
        ArgumentNullException.ThrowIfNull(cache);

        _cache = cache;
    }

    /// <inheritdoc/>
    public async ValueTask InsertAsync(RefreshTokenGrant grant, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(grant);
        cancellationToken.ThrowIfCancellationRequested();

        await WriteGrantAsync(grant, cancellationToken).ConfigureAwait(false);

        var handleHash = grant.HandleHash.ToString();
        await AddToIndexAsync(BuildFamilyIndexKey(grant.FamilyId), handleHash, grant.FamilyAbsoluteExpiry, cancellationToken).ConfigureAwait(false);
        await AddToIndexAsync(BuildSubjectIndexKey(grant.Subject), handleHash, grant.FamilyAbsoluteExpiry, cancellationToken).ConfigureAwait(false);
    }

    /// <inheritdoc/>
    public async ValueTask<RefreshTokenGrant?> FindByHandleAsync(StoreKey handleHash, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();

        return await ReadGrantAsync(handleHash.ToString(), cancellationToken).ConfigureAwait(false);
    }

    /// <inheritdoc/>
    public async ValueTask<bool> TryMarkConsumedAsync(StoreKey handleHash, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();

        // Not atomic — see type-level "Non-atomic consumption" remarks.
        var current = await ReadGrantAsync(handleHash.ToString(), cancellationToken).ConfigureAwait(false);
        if (current is null || current.Status != RefreshGrantStatus.Active)
            return false;

        await WriteGrantAsync(current with { Status = RefreshGrantStatus.Consumed }, cancellationToken).ConfigureAwait(false);
        return true;
    }

    /// <inheritdoc/>
    public async ValueTask RevokeFamilyAsync(string familyId, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(familyId);
        cancellationToken.ThrowIfCancellationRequested();

        await RevokeIndexedGrantsAsync(BuildFamilyIndexKey(familyId), cancellationToken).ConfigureAwait(false);
    }

    /// <inheritdoc/>
    public async ValueTask RevokeBySubjectAsync(string subject, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(subject);
        cancellationToken.ThrowIfCancellationRequested();

        await RevokeIndexedGrantsAsync(BuildSubjectIndexKey(subject), cancellationToken).ConfigureAwait(false);
    }

    private async Task RevokeIndexedGrantsAsync(string indexKey, CancellationToken cancellationToken)
    {
        var index = await ReadIndexAsync(indexKey, cancellationToken).ConfigureAwait(false);
        if (index is null)
            return;

        foreach (var handleHash in index.HandleHashes)
        {
            var grant = await ReadGrantAsync(handleHash, cancellationToken).ConfigureAwait(false);
            if (grant is null || grant.Status == RefreshGrantStatus.Revoked)
                continue;

            await WriteGrantAsync(grant with { Status = RefreshGrantStatus.Revoked }, cancellationToken).ConfigureAwait(false);
        }
    }

    private async Task WriteGrantAsync(RefreshTokenGrant grant, CancellationToken cancellationToken)
    {
        try
        {
            var record = RefreshTokenGrantRecord.FromGrant(grant);
            var json = JsonSerializer.SerializeToUtf8Bytes(
                record, StoreJsonSerializerContext.Default.RefreshTokenGrantRecord);

            var options = new DistributedCacheEntryOptions { AbsoluteExpiration = grant.FamilyAbsoluteExpiry };
            await _cache.SetAsync(BuildGrantKey(grant.HandleHash.ToString()), json, options, cancellationToken)
                .ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is not (ZeeKayDaStoreException or OperationCanceledException))
        {
            throw new ZeeKayDaStoreException("Failed to store the refresh token grant in the distributed cache.", ex);
        }
    }

    private async Task<RefreshTokenGrant?> ReadGrantAsync(string handleHash, CancellationToken cancellationToken)
    {
        byte[]? bytes;
        try
        {
            bytes = await _cache.GetAsync(BuildGrantKey(handleHash), cancellationToken).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is not (ZeeKayDaStoreException or OperationCanceledException))
        {
            throw new ZeeKayDaStoreException("Failed to read the refresh token grant from the distributed cache.", ex);
        }

        if (bytes is null)
            return null;

        try
        {
            var record = JsonSerializer.Deserialize(
                bytes, StoreJsonSerializerContext.Default.RefreshTokenGrantRecord)!;
            return record.ToGrant();
        }
        catch (Exception ex) when (ex is not ZeeKayDaStoreException)
        {
            // Deserialization failure is data corruption, not "confirmed absent" — the
            // fail-closed contract (ADR 0014 §3) requires this to propagate, not become null.
            throw new ZeeKayDaStoreException("Failed to parse the refresh token grant read from the distributed cache.", ex);
        }
    }

    private async Task AddToIndexAsync(string indexKey, string handleHash, DateTimeOffset familyAbsoluteExpiry, CancellationToken cancellationToken)
    {
        var existing = await ReadIndexAsync(indexKey, cancellationToken).ConfigureAwait(false);

        var handleHashes = existing is null
            ? [handleHash]
            : existing.HandleHashes.Contains(handleHash, StringComparer.Ordinal)
                ? existing.HandleHashes
                : [.. existing.HandleHashes, handleHash];

        var expiresAt = existing is null ? familyAbsoluteExpiry : Max(existing.ExpiresAt, familyAbsoluteExpiry);

        await WriteIndexAsync(indexKey, new RefreshTokenGrantIndexEnvelope(handleHashes, expiresAt), cancellationToken)
            .ConfigureAwait(false);
    }

    private async Task<RefreshTokenGrantIndexEnvelope?> ReadIndexAsync(string indexKey, CancellationToken cancellationToken)
    {
        byte[]? bytes;
        try
        {
            bytes = await _cache.GetAsync(indexKey, cancellationToken).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is not (ZeeKayDaStoreException or OperationCanceledException))
        {
            throw new ZeeKayDaStoreException("Failed to read a refresh token grant revocation index from the distributed cache.", ex);
        }

        if (bytes is null)
            return null;

        try
        {
            return JsonSerializer.Deserialize(
                bytes, StoreJsonSerializerContext.Default.RefreshTokenGrantIndexEnvelope);
        }
        catch (Exception ex) when (ex is not ZeeKayDaStoreException)
        {
            throw new ZeeKayDaStoreException("Failed to parse a refresh token grant revocation index.", ex);
        }
    }

    private async Task WriteIndexAsync(string indexKey, RefreshTokenGrantIndexEnvelope envelope, CancellationToken cancellationToken)
    {
        try
        {
            var json = JsonSerializer.SerializeToUtf8Bytes(
                envelope, StoreJsonSerializerContext.Default.RefreshTokenGrantIndexEnvelope);

            var options = new DistributedCacheEntryOptions { AbsoluteExpiration = envelope.ExpiresAt };
            await _cache.SetAsync(indexKey, json, options, cancellationToken).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is not (ZeeKayDaStoreException or OperationCanceledException))
        {
            throw new ZeeKayDaStoreException("Failed to store a refresh token grant revocation index in the distributed cache.", ex);
        }
    }

    private static string BuildGrantKey(string handleHash) => $"zkd:rtg:{handleHash}";
    private static string BuildFamilyIndexKey(string familyId) => $"zkd:rtg:family:{familyId}";
    private static string BuildSubjectIndexKey(string subject) => $"zkd:rtg:subject:{subject}";

    private static DateTimeOffset Max(DateTimeOffset a, DateTimeOffset b) => a > b ? a : b;
}
