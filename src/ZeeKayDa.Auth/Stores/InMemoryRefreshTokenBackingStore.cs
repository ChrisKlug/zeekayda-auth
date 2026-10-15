using System.Collections.Concurrent;

namespace ZeeKayDa.Auth.Stores;

/// <summary>The default in-process <see cref="IRefreshTokenBackingStore"/>, storing grants exactly as received.</summary>
/// <remarks>
/// <strong>Single instance only:</strong> on several instances, grants on one are invisible to another, which
/// silently disables single use and reuse detection (RFC 9700 §4.14.2). Revoke scans hold a write lock that
/// inserts take the read side of, so a grant inserted mid-revoke cannot be missed (RFC 9700 §4.13).
/// </remarks>
internal sealed class InMemoryRefreshTokenBackingStore : IRefreshTokenBackingStore
{
    private readonly ConcurrentDictionary<StoreKey, RefreshTokenGrant> _grants = new();

    // Never forgotten, like the grants: rememberUntil is only a floor on how long to keep a record.
    private readonly ConcurrentDictionary<string, byte> _revokedFamilies = new(StringComparer.Ordinal);
    private readonly ReaderWriterLockSlim _revokeLock = new(LockRecursionPolicy.NoRecursion);

    /// <inheritdoc/>
    public Task InsertAsync(RefreshTokenGrant grant, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(grant);
        cancellationToken.ThrowIfCancellationRequested();

        _revokeLock.EnterReadLock();
        try
        {
            if (!_grants.TryAdd(grant.HandleHash, grant))
                throw new ZeeKayDaStoreException(
                    "The refresh token handle collided with an existing grant.");
        }
        finally
        {
            _revokeLock.ExitReadLock();
        }

        return Task.CompletedTask;
    }

    /// <inheritdoc/>
    public Task<RefreshTokenGrant?> FindByHandleAsync(StoreKey handleHash, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();

        return Task.FromResult(_grants.TryGetValue(handleHash, out var grant) ? grant : null);
    }

    /// <inheritdoc/>
    public Task<bool> TryMarkConsumedAsync(StoreKey handleHash, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();

        if (!_grants.TryGetValue(handleHash, out var current) || current.Status != RefreshGrantStatus.Active)
            return Task.FromResult(false);

        var updated = current with { Status = RefreshGrantStatus.Consumed };
        return Task.FromResult(_grants.TryUpdate(handleHash, updated, current));
    }

    /// <inheritdoc/>
    public Task RevokeFamilyAsync(string familyId, DateTimeOffset rememberUntil, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(familyId);
        cancellationToken.ThrowIfCancellationRequested();

        _revokedFamilies.TryAdd(familyId, 0);
        RevokeWhere(grant => string.Equals(grant.FamilyId, familyId, StringComparison.Ordinal));

        return Task.CompletedTask;
    }

    /// <inheritdoc/>
    public Task RevokeBySubjectAsync(string subject, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(subject);
        cancellationToken.ThrowIfCancellationRequested();

        RevokeWhere(grant => string.Equals(grant.Subject, subject, StringComparison.Ordinal));

        return Task.CompletedTask;
    }

    /// <inheritdoc/>
    public Task<bool> IsFamilyRevokedAsync(string familyId, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(familyId);
        cancellationToken.ThrowIfCancellationRequested();

        return Task.FromResult(_revokedFamilies.ContainsKey(familyId));
    }

    private void RevokeWhere(Func<RefreshTokenGrant, bool> predicate)
    {
        _revokeLock.EnterWriteLock();
        try
        {
            foreach (var (key, current) in _grants)
            {
                if (!predicate(current) || current.Status == RefreshGrantStatus.Revoked)
                    continue;

                var revoked = current with { Status = RefreshGrantStatus.Revoked };

                // Losing the CAS means a concurrent consume made the row terminal: no longer Active either way.
                _grants.TryUpdate(key, revoked, current);
            }
        }
        finally
        {
            _revokeLock.ExitWriteLock();
        }
    }
}
