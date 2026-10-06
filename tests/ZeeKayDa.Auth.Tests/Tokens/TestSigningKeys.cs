using System.Security.Cryptography;
using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.Tests.Tokens;

/// <summary>
/// Builds real <see cref="SigningKeySet"/> and <see cref="SigningKeyRing"/> instances from key
/// material, so tests that need a key set or a ring do not each repeat the crypto boilerplate — and
/// never disagree about it.
/// </summary>
internal static class TestSigningKeys
{
    /// <summary>
    /// Builds a key set whose signing key uses <paramref name="signingAlgorithm"/>, optionally
    /// publishing further keys under <paramref name="alsoPublished"/>. At most two extra algorithms
    /// can be published: the set has exactly three slots (Previous/Current/Next).
    /// </summary>
    public static SigningKeySet KeySet(
        SigningAlgorithm signingAlgorithm, params SigningAlgorithm[] alsoPublished)
    {
        var current = SourceKey("current", signingAlgorithm);
        var previous = alsoPublished.Length > 0 ? SourceKey("previous", alsoPublished[0]) : null;
        var next = alsoPublished.Length > 1 ? SourceKey("next", alsoPublished[1]) : null;

        return SigningKeySetBuilder.Build(SourceKeySet.Create(previous, current, next));
    }

    /// <summary>
    /// Builds an initialized ring whose signing key uses <paramref name="signingAlgorithm"/>,
    /// optionally publishing further keys under <paramref name="alsoPublished"/> (at most two).
    /// </summary>
    public static SigningKeyRing Ring(SigningAlgorithm signingAlgorithm, params SigningAlgorithm[] alsoPublished)
    {
        using var privateKey = PrivateKey(signingAlgorithm);
        var current = SourceKey("current", signingAlgorithm, privateKey);
        var previous = alsoPublished.Length > 0 ? SourceKey("previous", alsoPublished[0]) : null;
        var next = alsoPublished.Length > 1 ? SourceKey("next", alsoPublished[1]) : null;

        return Ring(SourceKeySet.Create(previous, current, next), privateKey);
    }

    /// <summary>
    /// Builds a ring over <paramref name="keys"/> and initializes it, signing with a copy of
    /// <paramref name="signingPrivateKey"/>, which must pair with <paramref name="keys"/>' signing key.
    /// <paramref name="decorateSigner"/>, when given, wraps the signer the source hands the ring.
    /// </summary>
    public static SigningKeyRing Ring(
        SourceKeySet keys, AsymmetricAlgorithm signingPrivateKey, TimeProvider? timeProvider = null,
        Func<ISigner, ISigner>? decorateSigner = null)
    {
        var ring = new SigningKeyRing(
            new InMemorySource(keys, signingPrivateKey, decorateSigner), timeProvider ?? TimeProvider.System);

        // Every await in initialization completes synchronously over an in-memory source and a
        // LocalSigner, so this never blocks; a ring that did would be a broken fixture, not a wait.
        var initialization = ring.EnsureInitializedAsync(CancellationToken.None);
        if (!initialization.IsCompleted)
            throw new InvalidOperationException("The in-memory signing key ring did not initialize synchronously.");
        initialization.GetAwaiter().GetResult();

        return ring;
    }

    /// <summary>Builds a ring over <paramref name="keys"/> without initializing it.</summary>
    public static SigningKeyRing Uninitialized(SourceKeySet keys, AsymmetricAlgorithm signingPrivateKey, TimeProvider? timeProvider = null)
        => new(new InMemorySource(keys, signingPrivateKey, decorateSigner: null), timeProvider ?? TimeProvider.System);

    /// <summary>Builds a ring over one freshly generated key without initializing it.</summary>
    public static SigningKeyRing Uninitialized(SigningAlgorithm algorithm)
    {
        using var privateKey = PrivateKey(algorithm);
        return Uninitialized(SourceKeySet.Create(previous: null, SourceKey("current", algorithm, privateKey), next: null), privateKey);
    }

    /// <summary>Builds a ring whose initialization fails with <paramref name="failure"/>, raised by the source's read.</summary>
    public static SigningKeyRing Failing(ZeeKayDaConfigurationFailure failure)
        => new(new FailingSource(failure), TimeProvider.System);

    /// <summary>Generates one key of the type and strength <paramref name="algorithm"/> requires.</summary>
    public static SourceKey SourceKey(string id, SigningAlgorithm algorithm)
    {
        using var privateKey = PrivateKey(algorithm);
        return SourceKey(id, algorithm, privateKey);
    }

    /// <summary>Reports the public half of <paramref name="privateKey"/> as a key with no expiry.</summary>
    public static SourceKey SourceKey(string id, SigningAlgorithm algorithm, AsymmetricAlgorithm privateKey)
        => new(new SourceKeyId(id), algorithm, PublicKey(privateKey), ExpiresAt: null);

    /// <summary>Generates a private key of the type and strength <paramref name="algorithm"/> requires.</summary>
    public static AsymmetricAlgorithm PrivateKey(SigningAlgorithm algorithm) => algorithm switch
    {
        SigningAlgorithm.ES256 or SigningAlgorithm.ES384 or SigningAlgorithm.ES512 => ECDsa.Create(Curve(algorithm)),
        _ => RSA.Create(2048),
    };

    private static PublicKeyParameters PublicKey(AsymmetricAlgorithm key) => key switch
    {
        ECDsa ec => PublicKeyParameters.FromEc(ec.ExportParameters(includePrivateParameters: false)),
        RSA rsa => PublicKeyParameters.FromRsa(rsa.ExportParameters(includePrivateParameters: false)),
        _ => throw new ArgumentException($"Unsupported key type {key.GetType().Name}.", nameof(key)),
    };

    private static AsymmetricAlgorithm Copy(AsymmetricAlgorithm key) => key switch
    {
        ECDsa ec => ECDsa.Create(ec.ExportParameters(includePrivateParameters: true)),
        RSA rsa => RSA.Create(rsa.ExportParameters(includePrivateParameters: true)),
        _ => throw new ArgumentException($"Unsupported key type {key.GetType().Name}.", nameof(key)),
    };

    private static ECCurve Curve(SigningAlgorithm algorithm) => algorithm switch
    {
        SigningAlgorithm.ES256 => ECCurve.NamedCurves.nistP256,
        SigningAlgorithm.ES384 => ECCurve.NamedCurves.nistP384,
        _ => ECCurve.NamedCurves.nistP521,
    };

    /// <summary>
    /// Reports <paramref name="keys"/> and signs with a private key copied at construction, so the
    /// caller keeps ownership of the key it passed.
    /// </summary>
    private sealed class InMemorySource(
        SourceKeySet keys, AsymmetricAlgorithm signingPrivateKey, Func<ISigner, ISigner>? decorateSigner)
        : ISigningKeySource, IDisposable
    {
        private readonly AsymmetricAlgorithm _privateKey = Copy(signingPrivateKey);

        public Task<SourceKeySet> ReadAsync(CancellationToken cancellationToken = default) => Task.FromResult(keys);

        public Task<ISigner> CreateSignerAsync(SourceKeyId id, CancellationToken cancellationToken = default)
        {
            ISigner signer = new LocalSigner(keys.SigningKey.Algorithm, Copy(_privateKey));
            return Task.FromResult(decorateSigner is null ? signer : decorateSigner(signer));
        }

        public void Dispose() => _privateKey.Dispose();
    }

    private sealed class FailingSource(ZeeKayDaConfigurationFailure failure) : ISigningKeySource
    {
        public Task<SourceKeySet> ReadAsync(CancellationToken cancellationToken = default)
            => throw new ZeeKayDaConfigurationException(failure);

        public Task<ISigner> CreateSignerAsync(SourceKeyId id, CancellationToken cancellationToken = default)
            => throw new NotSupportedException();
    }
}
