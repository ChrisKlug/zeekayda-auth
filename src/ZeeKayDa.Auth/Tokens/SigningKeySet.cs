using System.Security.Cryptography;

namespace ZeeKayDa.Auth.Tokens;

/// <summary>
/// Pairs a public <see cref="SigningKeyDescriptor"/> with its corresponding private key.
/// </summary>
public readonly struct SigningKeyPair
{
    /// <summary>Gets the public key descriptor.</summary>
    public SigningKeyDescriptor Descriptor { get; init; }

    /// <summary>Gets the private key used for signing.</summary>
    public AsymmetricAlgorithm PrivateKey { get; init; }
}

/// <summary>
/// The set of currently trusted signing keys returned by <c>LoadKeysAsync</c> on the
/// <see cref="JwtSigningService{TOptions}"/> base class.
/// </summary>
/// <remarks>
/// <para>
/// This type holds the active signing key and any keys still within their retirement window,
/// together with the private key material needed to perform signatures. The private key objects
/// (<see cref="AsymmetricAlgorithm"/>) are <see cref="IDisposable"/>; the base class disposes
/// them deterministically when the set is superseded on refresh, rather than relying on the
/// garbage collector.
/// </para>
/// <para>
/// The first entry in <see cref="Keys"/> is always treated as the active signing key.
/// </para>
/// <para>
/// Reference counting ensures that private key objects are never disposed while an in-flight
/// <c>SignAsync</c> call is still using them. Call <see cref="TryBorrow"/> before accessing
/// private keys on the fast path and <see cref="Return"/> when done. <see cref="Dispose"/>
/// decrements the count and releases the underlying key material once all borrows have returned.
/// </para>
/// </remarks>
public sealed class SigningKeySet : IDisposable
{
    private readonly AsymmetricAlgorithm[] _privateKeys;

    // Refcount starts at 1 (representing the "cache holds a reference" borrow).
    // Additional borrows increment this before use and decrement after.
    // When the count reaches zero, the private keys are disposed.
    // Use int so Interlocked.Decrement can return the post-decrement value atomically.
    private int _refCount = 1;

    // 0 = live, 1 = disposed. int so Interlocked.Exchange can make the transition atomic.
    private int _disposed;

    /// <summary>
    /// Initialises a new <see cref="SigningKeySet"/> from an ordered list of key pairs.
    /// </summary>
    /// <param name="keys">
    /// The ordered list of key pairs. The first pair is the active signing key. Must be
    /// non-null and non-empty. The set takes ownership of each <see cref="SigningKeyPair.PrivateKey"/>
    /// and disposes them on <see cref="Dispose"/>.
    /// </param>
    public SigningKeySet(IReadOnlyList<SigningKeyPair> keys)
    {
        ArgumentNullException.ThrowIfNull(keys);

        if (keys.Count == 0)
            throw new ArgumentException("At least one signing key pair is required.", nameof(keys));

        _privateKeys = new AsymmetricAlgorithm[keys.Count];
        var descriptors = new SigningKeyDescriptor[keys.Count];

        for (var i = 0; i < keys.Count; i++)
        {
            descriptors[i] = keys[i].Descriptor;
            _privateKeys[i] = keys[i].PrivateKey;
        }

        // Pre-compute once for the set's lifetime. GetSigningKeysAsync is on the public
        // JWKS hot path and must not allocate on every call.
        Keys = Array.AsReadOnly(descriptors);
    }

    /// <summary>
    /// Gets the ordered key descriptors. The first entry is the active signing key. Stable for
    /// the lifetime of the set; returned directly from
    /// <see cref="JwtSigningService{TOptions}.GetSigningKeysAsync"/> without further allocation.
    /// </summary>
    public IReadOnlyList<SigningKeyDescriptor> Keys { get; }

    /// <summary>Gets the active (first) signing key descriptor.</summary>
    public SigningKeyDescriptor ActiveKey => Keys[0];

    /// <summary>
    /// Gets the private key at the given zero-based position. Used by the base class to
    /// perform the signing operation.
    /// </summary>
    /// <param name="index">Zero-based index into <see cref="Keys"/>.</param>
    public AsymmetricAlgorithm GetPrivateKey(int index)
    {
        ObjectDisposedException.ThrowIf(_disposed != 0, this);
        return _privateKeys[index];
    }

    /// <summary>
    /// Attempts to increment the borrow count so the caller can safely use the private keys.
    /// Returns <see langword="false"/> if the set has already been fully disposed (refcount
    /// already at zero), in which case the caller must not use this set.
    /// </summary>
    /// <remarks>
    /// Every successful <see cref="TryBorrow"/> must be balanced by exactly one call to
    /// <see cref="Return"/>.
    /// </remarks>
    internal bool TryBorrow()
    {
        // Spin-loop to atomically increment the refcount only if it is still > 0.
        // A CAS loop is used instead of a simple Interlocked.Increment to avoid
        // resurrecting a set whose count has already reached zero.
        int current;
        do
        {
            current = Volatile.Read(ref _refCount);
            if (current <= 0)
                return false;
        }
        while (Interlocked.CompareExchange(ref _refCount, current + 1, current) != current);

        return true;
    }

    /// <summary>
    /// Decrements the borrow count. When the count reaches zero the private key objects are
    /// disposed. Must be called exactly once for each successful <see cref="TryBorrow"/>.
    /// </summary>
    internal void Return()
    {
        var remaining = Interlocked.Decrement(ref _refCount);
        if (remaining == 0)
            DisposeKeys();
    }

    /// <summary>
    /// Releases the cache's own borrow (the initial refcount of 1). Private key objects are
    /// disposed only after all in-flight borrows have also been returned. Safe to call multiple
    /// times.
    /// </summary>
    public void Dispose()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0)
            return;

        Return();
    }

    private void DisposeKeys()
    {
        foreach (var key in _privateKeys)
            key.Dispose();
    }
}
