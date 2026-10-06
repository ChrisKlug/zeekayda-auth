using System.Security.Cryptography;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using ZeeKayDa.Auth.Logging;
using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.Tests.Tokens;

/// <summary>
/// Builds real <see cref="SigningKeySet"/> and <see cref="SigningKeyRing"/> instances from key
/// material, so tests that need a key set or a ring do not each repeat the crypto boilerplate — and
/// never disagree about it.
/// </summary>
internal static class TestSigningKeys
{
    /// <summary>A one-day lead time and one day of retention: a key signs once a day old, and the key
    /// it succeeds stays published until the successor is two days old.</summary>
    public static SigningKeyOptions Options => new()
    {
        LeadTime = TimeSpan.FromDays(1),
        RetainRetiredKeysFor = TimeSpan.FromDays(1),
    };

    /// <summary>A date that makes a key older than any key dated <see cref="SigningNotBefore"/>, and
    /// still published beside it.</summary>
    public static DateTimeOffset RetiringNotBefore => DateTimeOffset.UtcNow - TimeSpan.FromDays(10);

    /// <summary>A date past the lead time but inside the retention period, under <see cref="Options"/>:
    /// the newest key with it signs, and older keys stay published.</summary>
    public static DateTimeOffset SigningNotBefore => DateTimeOffset.UtcNow - TimeSpan.FromHours(36);

    /// <summary>A date inside the lead time: a key with it is published but does not sign yet.</summary>
    public static DateTimeOffset StagedNotBefore => DateTimeOffset.UtcNow - TimeSpan.FromHours(1);

    /// <summary>
    /// Builds a key set whose signing key uses <paramref name="signingAlgorithm"/>, publishing at
    /// most two further keys: the first older than the signing key, the second staged.
    /// </summary>
    public static SigningKeySet KeySet(
        SigningAlgorithm signingAlgorithm, params SigningAlgorithm[] alsoPublished)
    {
        using var privateKey = PrivateKey(signingAlgorithm);
        return SigningKeySetBuilder.Build(
            Keys(signingAlgorithm, privateKey, alsoPublished), DateTimeOffset.UtcNow, Options, NullLogger.Instance);
    }

    /// <summary>
    /// Builds an initialized ring whose signing key uses <paramref name="signingAlgorithm"/>,
    /// publishing at most two further keys: the first older than the signing key, the second staged.
    /// </summary>
    public static SigningKeyRing Ring(SigningAlgorithm signingAlgorithm, params SigningAlgorithm[] alsoPublished)
    {
        using var privateKey = PrivateKey(signingAlgorithm);
        return Ring(Keys(signingAlgorithm, privateKey, alsoPublished), privateKey);
    }

    /// <summary>
    /// Builds a ring over <paramref name="keys"/> and initializes it, signing with a copy of
    /// <paramref name="signingPrivateKey"/>, which must pair with whichever key the ring chooses.
    /// <paramref name="decorateSigner"/>, when given, wraps the signer the source hands the ring.
    /// </summary>
    public static SigningKeyRing Ring(
        IReadOnlyList<SourceKey> keys, AsymmetricAlgorithm signingPrivateKey, TimeProvider? timeProvider = null,
        Func<ISigner, ISigner>? decorateSigner = null, SanitizingLogger<SigningKeyRing>? logger = null)
    {
        var ring = new SigningKeyRing(
            new InMemorySource(keys, signingPrivateKey, decorateSigner),
            timeProvider ?? TimeProvider.System,
            Options,
            logger ?? new CapturingSanitizingLogger<SigningKeyRing>());

        // Every await in initialization completes synchronously over an in-memory source and a
        // LocalSigner, so this never blocks; a ring that did would be a broken fixture, not a wait.
        var initialization = ring.EnsureInitializedAsync(CancellationToken.None);
        if (!initialization.IsCompleted)
            throw new InvalidOperationException("The in-memory signing key ring did not initialize synchronously.");
        initialization.GetAwaiter().GetResult();

        return ring;
    }

    /// <summary>Builds a ring over <paramref name="keys"/> without initializing it.</summary>
    public static SigningKeyRing Uninitialized(
        IReadOnlyList<SourceKey> keys, AsymmetricAlgorithm signingPrivateKey, TimeProvider? timeProvider = null,
        Func<ISigner, ISigner>? decorateSigner = null)
        => new(
            new InMemorySource(keys, signingPrivateKey, decorateSigner),
            timeProvider ?? TimeProvider.System,
            Options,
            new CapturingSanitizingLogger<SigningKeyRing>());

    /// <summary>Builds a ring over one freshly generated key without initializing it.</summary>
    public static SigningKeyRing Uninitialized(SigningAlgorithm algorithm)
    {
        using var privateKey = PrivateKey(algorithm);
        return Uninitialized([SourceKey("current", algorithm, privateKey)], privateKey);
    }

    /// <summary>Builds a ring whose initialization fails with <paramref name="failure"/>, raised by the source's read.</summary>
    public static SigningKeyRing Failing(ZeeKayDaConfigurationFailure failure)
        => new(new FailingSource(failure), TimeProvider.System, Options, new CapturingSanitizingLogger<SigningKeyRing>());

    /// <summary>
    /// Registers what <c>AddZeeKayDaAuthCore</c> provides and the ring's registration resolves —
    /// the server options and the sanitizing logger — for tests that build a bare builder.
    /// </summary>
    public static IServiceCollection AddRingDependencies(this IServiceCollection services)
    {
        services.AddOptions<AuthorizationServerOptions>()
            .Configure(options => options.SigningKeys.RetainRetiredKeysFor = TimeSpan.FromHours(1));
        services.TryAddSingleton(typeof(ILogger<>), typeof(NullLogger<>));
        services.TryAddSingleton(typeof(SanitizingLogger<>), typeof(RegisteredSanitizingLogger<>));
        return services;
    }

    /// <summary>Generates one key of the type and strength <paramref name="algorithm"/> requires.</summary>
    public static SourceKey SourceKey(string id, SigningAlgorithm algorithm, DateTimeOffset? notBefore = null)
    {
        using var privateKey = PrivateKey(algorithm);
        return SourceKey(id, algorithm, privateKey, notBefore);
    }

    /// <summary>Reports the public half of <paramref name="privateKey"/> as a key.</summary>
    public static SourceKey SourceKey(
        string id, SigningAlgorithm algorithm, AsymmetricAlgorithm privateKey,
        DateTimeOffset? notBefore = null, DateTimeOffset? expiresAt = null)
        => new(new SourceKeyId(id), algorithm, PublicKey(privateKey), notBefore, expiresAt);

    private static List<SourceKey> Keys(
        SigningAlgorithm signingAlgorithm, AsymmetricAlgorithm signingPrivateKey, SigningAlgorithm[] alsoPublished)
    {
        if (alsoPublished.Length == 0)
            return [SourceKey("current", signingAlgorithm, signingPrivateKey)];

        List<SourceKey> keys =
        [
            SourceKey("current", signingAlgorithm, signingPrivateKey, SigningNotBefore),
            SourceKey("previous", alsoPublished[0], RetiringNotBefore),
        ];
        if (alsoPublished.Length > 1)
            keys.Add(SourceKey("next", alsoPublished[1], StagedNotBefore));
        return keys;
    }

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
        IReadOnlyList<SourceKey> keys, AsymmetricAlgorithm signingPrivateKey, Func<ISigner, ISigner>? decorateSigner)
        : ISigningKeySource, IDisposable
    {
        private readonly AsymmetricAlgorithm _privateKey = Copy(signingPrivateKey);

        public Task<IReadOnlyList<SourceKey>> ReadAsync(CancellationToken cancellationToken = default) => Task.FromResult(keys);

        public Task<ISigner> CreateSignerAsync(SourceKeyId id, CancellationToken cancellationToken = default)
        {
            ISigner signer = new LocalSigner(keys.Single(key => key.Id == id).Algorithm, Copy(_privateKey));
            return Task.FromResult(decorateSigner is null ? signer : decorateSigner(signer));
        }

        public void Dispose() => _privateKey.Dispose();
    }

    private sealed class FailingSource(ZeeKayDaConfigurationFailure failure) : ISigningKeySource
    {
        public Task<IReadOnlyList<SourceKey>> ReadAsync(CancellationToken cancellationToken = default)
            => throw new ZeeKayDaConfigurationException(failure);

        public Task<ISigner> CreateSignerAsync(SourceKeyId id, CancellationToken cancellationToken = default)
            => throw new NotSupportedException();
    }
}
