using System.Collections.Concurrent;

namespace ZeeKayDa.Auth.Stores;

/// <summary>
/// Default <see cref="IAuthorizationCodeBackingStore"/> implementation backed by a
/// <see cref="ConcurrentDictionary{TKey,TValue}"/>.
/// </summary>
/// <remarks>
/// <para>
/// <strong>Atomicity.</strong> <see cref="TryInsertAsync"/> uses
/// <see cref="ConcurrentDictionary{TKey,TValue}.TryAdd"/>, which is natively atomic — this
/// satisfies the one hard invariant <see cref="IAuthorizationCodeBackingStore"/> requires
/// (ADR 0013 §3, §10) without any locking of its own.
/// </para>
/// <para>
/// <strong>Single-instance is a deployment invariant, not a recommendation.</strong>
/// Running multiple instances of this host with the in-memory default silently disables
/// single-use enforcement (RFC 9700 §2.1.1) and refresh token reuse detection
/// (RFC 9700 §4.14.2): codes issued by instance A are invisible to instance B. Multi-instance
/// deployments MUST replace this store with one backed by a shared, atomic backend.
/// </para>
/// <para>
/// This type has no knowledge of OAuth, tombstones, encryption, or expiry — the framework's
/// <c>AuthorizationCodeStore</c> coordinator owns all of that (ADR 0013 §1); this store just
/// holds opaque bytes under already-hashed keys.
/// </para>
/// </remarks>
internal sealed class InMemoryAuthorizationCodeBackingStore : IAuthorizationCodeBackingStore
{
    private readonly ConcurrentDictionary<StoreKey, byte[]> _entries = new();

    /// <inheritdoc/>
    public ValueTask<bool> TryInsertAsync(StoreKey key, ReadOnlyMemory<byte> value, DateTimeOffset expiresAt, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();

        return ValueTask.FromResult(_entries.TryAdd(key, value.ToArray()));
    }

    /// <inheritdoc/>
    public ValueTask<ReadOnlyMemory<byte>?> GetAsync(StoreKey key, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();

        return ValueTask.FromResult(_entries.TryGetValue(key, out var value) ? (ReadOnlyMemory<byte>?)value : null);
    }

    /// <inheritdoc/>
    public ValueTask RemoveAsync(StoreKey key, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();

        _entries.TryRemove(key, out _);
        return ValueTask.CompletedTask;
    }
}
