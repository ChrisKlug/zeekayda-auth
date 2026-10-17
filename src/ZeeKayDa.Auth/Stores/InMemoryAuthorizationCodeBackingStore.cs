using System.Collections.Concurrent;

namespace ZeeKayDa.Auth.Stores;

/// <summary>The default in-process <see cref="IAuthorizationCodeBackingStore"/>; <c>TryAdd</c> makes inserts atomic.</summary>
/// <remarks>
/// <strong>Single instance only:</strong> on several instances, codes issued on one are invisible to another,
/// which silently disables single use (RFC 9700 §2.1.1).
/// </remarks>
internal sealed class InMemoryAuthorizationCodeBackingStore(TimeProvider timeProvider) : IAuthorizationCodeBackingStore
{
    private readonly ConcurrentDictionary<StoreKey, Entry> _entries = new();

    /// <inheritdoc/>
    public Task<bool> TryInsertAsync(StoreKey key, ReadOnlyMemory<byte> value, DateTimeOffset expiresAt, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();

        // Every code, tombstone and interaction claim would otherwise be held for the life of the process.
        RemoveExpired();

        return Task.FromResult(_entries.TryAdd(key, new Entry(value.ToArray(), expiresAt)));
    }

    /// <inheritdoc/>
    public Task<ReadOnlyMemory<byte>?> GetAsync(StoreKey key, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();

        return Task.FromResult(_entries.TryGetValue(key, out var entry) ? (ReadOnlyMemory<byte>?)entry.Value : null);
    }

    /// <inheritdoc/>
    public Task RemoveAsync(StoreKey key, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();

        _entries.TryRemove(key, out _);
        return Task.CompletedTask;
    }

    /// <summary>How many entries are held, expired or not. Observable only so the sweep can be tested.</summary>
    internal int Count => _entries.Count;

    /// <summary>Evicts at the caller's <c>expiresAt</c>, as a backend with native TTL may.</summary>
    private void RemoveExpired()
    {
        var now = timeProvider.GetUtcNow();
        foreach (var expired in _entries.Where(pair => now >= pair.Value.ExpiresAt))
            _entries.TryRemove(expired);
    }

    private sealed record Entry(byte[] Value, DateTimeOffset ExpiresAt);
}
