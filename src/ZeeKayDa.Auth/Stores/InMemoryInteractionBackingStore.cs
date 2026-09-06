using System.Collections.Concurrent;

namespace ZeeKayDa.Auth.Stores;

/// <summary>
/// <see cref="IInteractionBackingStore"/> for a single process: a concurrent dictionary, for
/// development and testing. An authorization request started on one instance cannot be
/// completed by another, so a multi-instance host must use a shared backend instead.
/// </summary>
internal sealed class InMemoryInteractionBackingStore : IInteractionBackingStore
{
    private readonly ConcurrentDictionary<StoreKey, Entry> _entries = new();
    private readonly TimeProvider _timeProvider;

    public InMemoryInteractionBackingStore(TimeProvider timeProvider)
    {
        ArgumentNullException.ThrowIfNull(timeProvider);

        _timeProvider = timeProvider;
    }

    /// <inheritdoc/>
    public ValueTask SetAsync(StoreKey key, ReadOnlyMemory<byte> value, DateTimeOffset expiresAt, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();

        // Abandoned requests — a closed tab, a user who never came back — would otherwise
        // accumulate for the life of the process. Sweeping on every write keeps the dictionary to
        // the live set at a cost proportional to it, which for a development host is nothing.
        RemoveExpired();

        _entries[key] = new Entry(value.ToArray(), expiresAt);
        return ValueTask.CompletedTask;
    }

    /// <inheritdoc/>
    public ValueTask<ReadOnlyMemory<byte>?> GetAsync(StoreKey key, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();

        return ValueTask.FromResult(
            _entries.TryGetValue(key, out var entry) && !IsExpired(entry) ? (ReadOnlyMemory<byte>?)entry.Value : null);
    }

    /// <inheritdoc/>
    public ValueTask RemoveAsync(StoreKey key, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();

        _entries.TryRemove(key, out _);
        return ValueTask.CompletedTask;
    }

    /// <summary>How many entries are held, expired or not. Observable only so the sweep can be tested.</summary>
    internal int Count => _entries.Count;

    private void RemoveExpired()
    {
        foreach (var expired in _entries.Where(pair => IsExpired(pair.Value)))
            _entries.TryRemove(expired.Key, out _);
    }

    private bool IsExpired(Entry entry) => _timeProvider.GetUtcNow() >= entry.ExpiresAt;

    private sealed record Entry(byte[] Value, DateTimeOffset ExpiresAt);
}
