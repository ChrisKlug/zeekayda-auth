using System.Security.Cryptography;

namespace ZeeKayDa.Auth.Tokens;

/// <summary>
/// The shipped <see cref="ISigner"/> implementation over a local, in-process RSA or ECDsa private
/// key. Local providers (development, File/PEM, PFX, Windows Certificate Store) construct this in
/// <see cref="JwtSigningService{TOptions}.CreateSignerAsync"/> and never implement
/// <see cref="ISigner"/> themselves; only genuinely remote providers (Azure Key Vault remote
/// signing, a KMS, an HSM) implement <see cref="ISigner"/> directly, since the private key never
/// becomes local for those.
/// </summary>
/// <remarks>
/// Unlike a remote <see cref="ISigner"/>, this instance owns the private key it wraps outright —
/// nothing else references it — so <see cref="Dispose"/> unconditionally disposing it satisfies
/// <see cref="ISigner"/>'s "release only your own per-activation handle" contract exactly.
/// </remarks>
public sealed class LocalSigner : ISigner
{
    private readonly SigningAlgorithm _algorithm;
    private readonly AsymmetricAlgorithm _privateKey;

    // 0 = live, 1 = disposed. int so Interlocked.Exchange makes the transition atomic.
    private int _disposed;

    /// <summary>
    /// Initialises a <see cref="LocalSigner"/> over a local private key.
    /// </summary>
    /// <param name="algorithm">The signing algorithm to use.</param>
    /// <param name="privateKey">
    /// The private key. Must be an <see cref="RSA"/> instance for an RSA <paramref name="algorithm"/>,
    /// or an <see cref="ECDsa"/> instance for an EC <paramref name="algorithm"/>. This instance takes
    /// ownership and disposes it on <see cref="Dispose"/>.
    /// </param>
    public LocalSigner(SigningAlgorithm algorithm, AsymmetricAlgorithm privateKey)
    {
        ArgumentNullException.ThrowIfNull(privateKey);

        _algorithm = algorithm;
        _privateKey = privateKey;
    }

    /// <inheritdoc/>
    public ValueTask<ReadOnlyMemory<byte>> SignAsync(
        ReadOnlyMemory<byte> signingInput, CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(_disposed != 0, this);

        return new ValueTask<ReadOnlyMemory<byte>>(SigningAlgorithms.Sign(_algorithm, signingInput.ToArray(), _privateKey));
    }

    /// <summary>
    /// Disposes the wrapped private key. Safe to call multiple times.
    /// </summary>
    public void Dispose()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0)
            return;

        _privateKey.Dispose();
    }

    /// <inheritdoc/>
    public SigningAlgorithm Algorithm => _algorithm;
}
