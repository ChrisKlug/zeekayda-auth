using System.Security.Cryptography;

namespace ZeeKayDa.Auth.Tokens;

/// <summary>
/// Pairs a public <see cref="SigningKeyDescriptor"/> with its corresponding private key.
/// </summary>
public readonly struct SigningKeyPair
{
    /// <summary>Gets the public key descriptor.</summary>
    public SigningKeyDescriptor Descriptor { get; init; }

    /// <summary>
    /// Gets the private key used for signing.
    /// </summary>
    /// <remarks>
    /// For a remote-signing provider (e.g. Azure Key Vault), this holds a public-only key handle
    /// rather than genuine private key material — Key Vault never releases the private key. It is
    /// still real, non-null key material used to validate algorithm/key-type compatibility at load
    /// time; a remote provider's <see cref="JwtSigningService{TOptions}.SignInputAsync"/> override
    /// signs via the remote API using the descriptor and does not read this property.
    /// </remarks>
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
/// <see cref="ActiveKey"/> is named explicitly at construction time; it is not inferred from
/// list position. <see cref="Keys"/> still happens to place the active key first (for
/// zero-allocation hot-path reuse and stable JWKS output), but that ordering is an
/// implementation detail, not the source of truth for which key is active.
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
    /// Initialises a new <see cref="SigningKeySet"/> from an explicitly named active key plus a
    /// lifecycle-neutral collection of additional trusted keys.
    /// </summary>
    /// <param name="activeKey">
    /// The key pair currently used to sign new tokens. This is the sole source of
    /// <see cref="ActiveKey"/> — it is no longer inferred from list position.
    /// </param>
    /// <param name="additionalKeys">
    /// Every other currently trusted key pair: keys published but not yet activated, and keys
    /// no longer signing but still inside their retirement window. Deliberately not split into
    /// separate "future" and "retired" buckets — the base class already treats both as a single
    /// "included but not active" list. May be <see langword="null"/> or empty. Duplicate
    /// <c>kid</c> values between <paramref name="activeKey"/> and <paramref name="additionalKeys"/>
    /// are not rejected here; that check stays at the base class's load path.
    /// </param>
    /// <remarks>
    /// The set takes ownership of each <see cref="SigningKeyPair.PrivateKey"/> and disposes them
    /// on <see cref="Dispose"/>.
    /// </remarks>
    public SigningKeySet(SigningKeyPair activeKey, IEnumerable<SigningKeyPair>? additionalKeys = null)
    {
        var additional = additionalKeys?.ToArray() ?? [];

        _privateKeys = new AsymmetricAlgorithm[additional.Length + 1];
        var descriptors = new SigningKeyDescriptor[additional.Length + 1];

        descriptors[0] = activeKey.Descriptor;
        _privateKeys[0] = activeKey.PrivateKey;

        for (var i = 0; i < additional.Length; i++)
        {
            descriptors[i + 1] = additional[i].Descriptor;
            _privateKeys[i + 1] = additional[i].PrivateKey;
        }

        // Pre-compute once for the set's lifetime. GetSigningKeysAsync is on the public
        // JWKS hot path and must not allocate on every call.
        Keys = Array.AsReadOnly(descriptors);
        ActiveKey = activeKey.Descriptor;
    }

    /// <summary>
    /// Gets the key descriptors, active key first followed by <c>additionalKeys</c> in their
    /// supplied order. This active-first ordering is retained purely as an implementation detail
    /// for zero-allocation reuse and stable JWKS output — JWKS array order carries no protocol
    /// meaning (RFC 7517 §5.1), and <see cref="ActiveKey"/> derives from the constructor's
    /// <c>activeKey</c> parameter, not from this array's position.
    /// </summary>
    public IReadOnlyList<SigningKeyDescriptor> Keys { get; }

    /// <summary>Gets the active signing key descriptor, as named at construction time.</summary>
    public SigningKeyDescriptor ActiveKey { get; }

    /// <summary>
    /// Gets the private key at the given zero-based position. Used by the base class to
    /// perform the signing operation. Index 0 corresponds to <see cref="ActiveKey"/> because
    /// the private-key array is built active-first, matching <see cref="Keys"/>.
    /// </summary>
    /// <param name="index">Zero-based index into <see cref="Keys"/>.</param>
    public AsymmetricAlgorithm GetPrivateKey(int index)
    {
        ObjectDisposedException.ThrowIf(_disposed != 0, this);
        return _privateKeys[index];
    }

    /// <summary>
    /// Gets the private key paired with <see cref="ActiveKey"/>. Prefer this over
    /// <see cref="GetPrivateKey(int)"/> when the caller's intent is "give me the active key's
    /// private key" — it names the concept directly rather than relying on the fact that the
    /// active key happens to sit at index 0 internally.
    /// </summary>
    public AsymmetricAlgorithm GetActivePrivateKey() => GetPrivateKey(0);

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
