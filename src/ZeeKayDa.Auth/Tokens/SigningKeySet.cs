using System.Security.Cryptography;

namespace ZeeKayDa.Auth.Tokens;

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
/// </remarks>
public sealed class SigningKeySet : IDisposable
{
    private readonly AsymmetricAlgorithm[] _privateKeys;
    private bool _disposed;

    /// <summary>
    /// Initialises a new <see cref="SigningKeySet"/> with an ordered list of key entries.
    /// </summary>
    /// <param name="keys">
    /// The ordered list of key entries. The first entry is the active signing key. Must be
    /// non-null and non-empty.
    /// </param>
    /// <param name="privateKeys">
    /// The private key objects corresponding to each entry in <paramref name="keys"/>. Must
    /// have the same length as <paramref name="keys"/>. The set takes ownership and disposes
    /// them on <see cref="Dispose"/>.
    /// </param>
    public SigningKeySet(IReadOnlyList<SigningKeyEntry> keys, AsymmetricAlgorithm[] privateKeys)
    {
        ArgumentNullException.ThrowIfNull(keys);
        ArgumentNullException.ThrowIfNull(privateKeys);

        if (keys.Count == 0)
            throw new ArgumentException("At least one signing key entry is required.", nameof(keys));

        if (keys.Count != privateKeys.Length)
            throw new ArgumentException("keys and privateKeys must have the same length.", nameof(privateKeys));

        Keys = keys;
        _privateKeys = privateKeys;

        // Pre-compute the descriptor list once for the set's lifetime. GetSigningKeysAsync
        // is on the public JWKS hot path and must not allocate on every call.
        Descriptors = keys.Select(e => e.Descriptor).ToList().AsReadOnly();
    }

    /// <summary>Gets the ordered key entries. The first entry is the active signing key.</summary>
    public IReadOnlyList<SigningKeyEntry> Keys { get; }

    /// <summary>
    /// Gets the pre-computed, read-only list of <see cref="SigningKeyDescriptor"/> instances for
    /// this set. Stable for the lifetime of the set; returned directly from
    /// <see cref="JwtSigningService{TOptions}.GetSigningKeysAsync"/> without further allocation.
    /// </summary>
    public IReadOnlyList<SigningKeyDescriptor> Descriptors { get; }

    /// <summary>Gets the active (first) signing key entry.</summary>
    public SigningKeyEntry ActiveKey => Keys[0];

    /// <summary>
    /// Gets the private key for the key at <paramref name="index"/>. Used by the base class
    /// to perform the signing operation.
    /// </summary>
    /// <param name="index">Zero-based index into <see cref="Keys"/>.</param>
    public AsymmetricAlgorithm GetPrivateKey(int index)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        return _privateKeys[index];
    }

    /// <summary>
    /// Disposes all private key objects owned by this set. Safe to call multiple times.
    /// </summary>
    public void Dispose()
    {
        if (_disposed)
            return;

        _disposed = true;
        foreach (var key in _privateKeys)
            key.Dispose();
    }
}
