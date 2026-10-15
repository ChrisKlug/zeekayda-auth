using System.Collections.Concurrent;

namespace ZeeKayDa.Auth.Stores;

/// <summary>The default in-process <see cref="IAuthorizationCodeBackingStore"/>; <c>TryAdd</c> makes inserts atomic.</summary>
/// <remarks>
/// <strong>Single instance only:</strong> on several instances, codes issued on one are invisible to another,
/// which silently disables single use (RFC 9700 §2.1.1).
/// </remarks>
internal sealed class InMemoryAuthorizationCodeBackingStore : IAuthorizationCodeBackingStore
{
    private readonly ConcurrentDictionary<StoreKey, byte[]> _entries = new();

    /// <inheritdoc/>
    public Task<bool> TryInsertAsync(StoreKey key, ReadOnlyMemory<byte> value, DateTimeOffset expiresAt, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();

        return Task.FromResult(_entries.TryAdd(key, value.ToArray()));
    }

    /// <inheritdoc/>
    public Task<ReadOnlyMemory<byte>?> GetAsync(StoreKey key, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();

        return Task.FromResult(_entries.TryGetValue(key, out var value) ? (ReadOnlyMemory<byte>?)value : null);
    }

    /// <inheritdoc/>
    public Task RemoveAsync(StoreKey key, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();

        _entries.TryRemove(key, out _);
        return Task.CompletedTask;
    }
}
