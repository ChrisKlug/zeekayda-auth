using System.Collections.Concurrent;

namespace ZeeKayDa.Auth.Stores;

/// <summary>
/// Default <see cref="IRefreshTokenGrantStore"/> implementation backed by an in-process
/// <see cref="ConcurrentDictionary{TKey,TValue}"/>.
/// </summary>
/// <remarks>
/// <para>
/// This is a thin storage adapter (ADR 0014 §1/§3): it has no knowledge of hashing, encryption,
/// expiry, or outcome selection — that protocol all lives in the sealed <c>RefreshTokenStore</c>
/// coordinator. This class stores and queries <see cref="RefreshTokenGrant"/> rows exactly as
/// received.
/// </para>
/// <para>
/// <strong>Single-instance is a deployment invariant, not a recommendation.</strong>
/// Running multiple instances of this host with the in-memory default silently disables
/// single-use enforcement and refresh token reuse detection (RFC 9700 §4.14.2): grants inserted
/// by instance A are invisible to instance B. Multi-instance deployments MUST replace this
/// store with one backed by a shared, atomic, queryable backend (see ADR 0014 §8).
/// </para>
/// <para>
/// <strong>Atomicity.</strong> <see cref="TryMarkConsumedAsync"/> uses
/// <see cref="ConcurrentDictionary{TKey,TValue}.TryUpdate(TKey,TValue,TValue)"/> as its
/// compare-and-set primitive, satisfying the interface's one hard invariant without a lock.
/// </para>
/// <para>
/// <strong>Revocation scans.</strong> <see cref="RevokeFamilyAsync"/> and
/// <see cref="RevokeBySubjectAsync"/> enumerate the whole dictionary. This is correct (complete
/// by construction — every entry is visited) and acceptable for an in-process, dev/test-sized
/// store; a relational or Cosmos backend would express the same completeness guarantee as an
/// indexed <c>UPDATE ... WHERE</c> instead.
/// </para>
/// </remarks>
internal sealed class InMemoryRefreshTokenGrantStore : IRefreshTokenGrantStore
{
    private readonly ConcurrentDictionary<StoreKey, RefreshTokenGrant> _grants = new();

    /// <inheritdoc/>
    public ValueTask InsertAsync(RefreshTokenGrant grant, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(grant);
        cancellationToken.ThrowIfCancellationRequested();

        if (!_grants.TryAdd(grant.HandleHash, grant))
            throw new ZeeKayDaStoreException(
                "The refresh token handle collided with an existing grant.");

        return ValueTask.CompletedTask;
    }

    /// <inheritdoc/>
    public ValueTask<RefreshTokenGrant?> FindByHandleAsync(StoreKey handleHash, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();

        return ValueTask.FromResult(_grants.TryGetValue(handleHash, out var grant) ? grant : null);
    }

    /// <inheritdoc/>
    public ValueTask<bool> TryMarkConsumedAsync(StoreKey handleHash, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();

        if (!_grants.TryGetValue(handleHash, out var current) || current.Status != RefreshGrantStatus.Active)
            return ValueTask.FromResult(false);

        var updated = current with { Status = RefreshGrantStatus.Consumed };
        return ValueTask.FromResult(_grants.TryUpdate(handleHash, updated, current));
    }

    /// <inheritdoc/>
    public ValueTask RevokeFamilyAsync(string familyId, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(familyId);
        cancellationToken.ThrowIfCancellationRequested();

        RevokeWhere(grant => string.Equals(grant.FamilyId, familyId, StringComparison.Ordinal));

        return ValueTask.CompletedTask;
    }

    /// <inheritdoc/>
    public ValueTask RevokeBySubjectAsync(string subject, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(subject);
        cancellationToken.ThrowIfCancellationRequested();

        RevokeWhere(grant => string.Equals(grant.Subject, subject, StringComparison.Ordinal));

        return ValueTask.CompletedTask;
    }

    private void RevokeWhere(Func<RefreshTokenGrant, bool> predicate)
    {
        foreach (var (key, current) in _grants)
        {
            if (!predicate(current) || current.Status == RefreshGrantStatus.Revoked)
                continue;

            var revoked = current with { Status = RefreshGrantStatus.Revoked };

            // A concurrent update losing this CAS means someone else already mutated the row
            // (e.g. a concurrent consume); the loop's completeness bar (every matching row ends
            // up Revoked) is preserved by re-checking on the next pass over this key is not
            // needed here because Consumed/Revoked are both terminal — either outcome already
            // satisfies "no longer Active", which is all that matters for family/subject revocation.
            _grants.TryUpdate(key, revoked, current);
        }
    }
}
