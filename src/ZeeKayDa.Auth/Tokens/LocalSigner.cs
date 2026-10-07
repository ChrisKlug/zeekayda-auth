using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace ZeeKayDa.Auth.Tokens;

/// <summary>
/// The shipped <see cref="ISigner"/> implementation over a local, in-process RSA or ECDsa private
/// key. Local providers (development, File/PEM, PFX, Windows Certificate Store) construct this in
/// <see cref="ISigningKeySource.CreateSignerAsync"/> and never implement
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

    /// <summary>
    /// Creates a <see cref="LocalSigner"/> over a certificate's private key.
    /// </summary>
    /// <param name="certificate">
    /// The certificate. The returned signer owns its own handle to the private key, so the caller may
    /// dispose <paramref name="certificate"/> straight away.
    /// </param>
    /// <param name="algorithm">The signing algorithm to use.</param>
    /// <exception cref="ArgumentOutOfRangeException">
    /// Thrown when <paramref name="algorithm"/> is not a defined <see cref="SigningAlgorithm"/> member.
    /// </exception>
    /// <exception cref="ZeeKayDaConfigurationException">
    /// Thrown with failure code <c>signing.certificate.private_key_not_found</c> when the certificate
    /// carries no private key, or one this process cannot access; or with the codes
    /// <see cref="SourceKey.FromCertificate"/> raises when its key does not suit <paramref name="algorithm"/>.
    /// </exception>
    public static LocalSigner FromCertificate(X509Certificate2 certificate, SigningAlgorithm algorithm)
    {
        ArgumentNullException.ThrowIfNull(certificate);
        if (!Enum.IsDefined(algorithm))
            throw new ArgumentOutOfRangeException(nameof(algorithm), algorithm, $"Not a defined {nameof(SigningAlgorithm)} member.");

        // Rejects a key type or curve that does not suit the algorithm, by the same rule the key set
        // applies, before any private key is opened.
        _ = SourceKey.FromCertificate(certificate, new SourceKeyId(certificate.Thumbprint), algorithm);

        if (!certificate.HasPrivateKey)
            throw PrivateKeyNotFound(certificate, "carries no private key");

        AsymmetricAlgorithm? privateKey;
        try
        {
            privateKey = certificate.GetRSAPrivateKey();
            privateKey ??= certificate.GetECDsaPrivateKey();
        }
        catch (CryptographicException ex)
        {
            throw PrivateKeyNotFound(certificate, "has a private key, but it could not be accessed", ex);
        }

        return privateKey is not null
            ? new LocalSigner(algorithm, privateKey)
            : throw PrivateKeyNotFound(certificate, "has a private key, but it could not be accessed");
    }

    // The cause travels as the inner exception, never its message in the failure text.
    private static ZeeKayDaConfigurationException PrivateKeyNotFound(
        X509Certificate2 certificate, string problem, CryptographicException? cause = null)
    {
        var failure = new ZeeKayDaConfigurationFailure(
            "signing.certificate.private_key_not_found",
            $"Certificate '{certificate.Subject}' (thumbprint {certificate.Thumbprint}) {problem}. Every listed " +
            "signing certificate must carry a private key this process can use, because any of them may be chosen to sign.");
        return cause is null ? new(failure) : new(failure, cause);
    }

    /// <inheritdoc/>
    public Task<ReadOnlyMemory<byte>> SignAsync(
        ReadOnlyMemory<byte> signingInput, CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(_disposed != 0, this);

        return Task.FromResult<ReadOnlyMemory<byte>>(SigningAlgorithms.Sign(_algorithm, signingInput.ToArray(), _privateKey));
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
}
