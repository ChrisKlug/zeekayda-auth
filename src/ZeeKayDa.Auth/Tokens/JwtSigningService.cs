using System.Buffers.Text;
using System.Diagnostics.CodeAnalysis;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Options;

namespace ZeeKayDa.Auth.Tokens;

/// <summary>
/// Abstract base class for <see cref="IJwtSigningService"/> implementations. Provides
/// interval-throttled caching, single-flight refresh coalescing, key-algorithm compatibility
/// validation, deterministic disposal of superseded private key material, and the JWS signing
/// operation. Implementors provide only <see cref="LoadKeysAsync"/>.
/// </summary>
/// <typeparam name="TOptions">
/// The provider-specific options type. Must derive from <see cref="JwtSigningServiceOptions"/>.
/// </typeparam>
public abstract class JwtSigningService<TOptions> : IJwtSigningService, IAsyncDisposable
    where TOptions : JwtSigningServiceOptions
{
    // OID values are stable across all platforms (macOS, Linux, Windows) unlike friendly names.
    private static readonly HashSet<string> AcceptedEcCurveOids =
        new(StringComparer.OrdinalIgnoreCase)
        {
            "1.2.840.10045.3.1.7", // P-256
            "1.3.132.0.34",        // P-384
            "1.3.132.0.35",        // P-521
        };

    private static readonly IReadOnlyDictionary<SigningAlgorithm, string> AlgorithmCurveOids =
        new Dictionary<SigningAlgorithm, string>
        {
            [SigningAlgorithm.ES256] = "1.2.840.10045.3.1.7", // P-256
            [SigningAlgorithm.ES384] = "1.3.132.0.34",        // P-384
            [SigningAlgorithm.ES512] = "1.3.132.0.35",        // P-521
        };

    private readonly TimeProvider _timeProvider;
    private readonly TimeSpan _refreshInterval;

    // Single-flight refresh gate: null means "no refresh in flight or cache valid".
    private readonly SemaphoreSlim _refreshLock = new(1, 1);
    private SigningKeySet? _cachedSet;
    private DateTimeOffset _cacheExpiresAt = DateTimeOffset.MinValue;

    /// <summary>
    /// Initialises the base class with options and a time provider.
    /// </summary>
    /// <param name="options">The provider-specific options.</param>
    /// <param name="timeProvider">
    /// The time provider used for cache-expiry calculations. Inject <see cref="TimeProvider"/>
    /// from DI or use <c>TimeProvider.System</c> in production and a
    /// <c>FakeTimeProvider</c> in tests.
    /// </param>
    protected JwtSigningService(IOptions<TOptions> options, TimeProvider timeProvider)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(timeProvider);

        _timeProvider = timeProvider;
        _refreshInterval = options.Value.RefreshInterval;
    }

    /// <summary>
    /// Loads the current set of trusted signing keys. Called by the base class at most once
    /// per <see cref="JwtSigningServiceOptions.RefreshInterval"/>; concurrent callers after
    /// the interval elapses are coalesced into a single load via the single-flight gate.
    /// </summary>
    /// <param name="cancellationToken">A token to cancel the operation.</param>
    /// <returns>
    /// The trusted key set. The first entry is the active signing key. Must never be empty.
    /// </returns>
    protected abstract ValueTask<SigningKeySet> LoadKeysAsync(CancellationToken cancellationToken);

    /// <inheritdoc/>
    public async ValueTask<IReadOnlyList<SigningKeyDescriptor>> GetSigningKeysAsync(
        CancellationToken cancellationToken = default)
    {
        var set = await GetOrRefreshCacheAsync(cancellationToken).ConfigureAwait(false);
        return set.Descriptors;
    }

    /// <inheritdoc/>
    public async ValueTask<SigningResult> SignAsync(
        ReadOnlyMemory<byte> payloadSegment,
        CancellationToken cancellationToken = default)
    {
        var set = await GetOrRefreshCacheAsync(cancellationToken).ConfigureAwait(false);
        return PerformSign(set, payloadSegment);
    }

    /// <inheritdoc/>
    public async ValueTask DisposeAsync()
    {
        await _refreshLock.WaitAsync().ConfigureAwait(false);
        try
        {
            _cachedSet?.Dispose();
            _cachedSet = null;
        }
        finally
        {
            _refreshLock.Release();
        }

        _refreshLock.Dispose();
        GC.SuppressFinalize(this);
    }

    private async ValueTask<SigningKeySet> GetOrRefreshCacheAsync(CancellationToken cancellationToken)
    {
        var now = _timeProvider.GetUtcNow();

        // Fast path: cache is still valid — avoid lock acquisition entirely.
        var current = Volatile.Read(ref _cachedSet);
        if (current is not null && now < _cacheExpiresAt)
            return current;

        // Cache is cold or expired: single-flight gate.
        await _refreshLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            // Re-check inside the lock; another caller may have refreshed while we waited.
            now = _timeProvider.GetUtcNow();
            if (_cachedSet is not null && now < _cacheExpiresAt)
                return _cachedSet;

            var previous = _cachedSet;
            var newSet = await LoadKeysAsync(cancellationToken).ConfigureAwait(false);

            ValidateKeySet(newSet);

            _cachedSet = newSet;
            _cacheExpiresAt = _timeProvider.GetUtcNow().Add(_refreshInterval);

            // Dispose the previous set's private keys now that we hold the lock and no
            // in-flight SignAsync can reference the old set (they all came through the same
            // lock path to reach the cache, or they used the previous Volatile.Read fast path
            // and have already completed their signing operation before we refreshed).
            previous?.Dispose();

            return newSet;
        }
        finally
        {
            _refreshLock.Release();
        }
    }

    private static SigningResult PerformSign(SigningKeySet set, ReadOnlyMemory<byte> payloadSegment)
    {
        var activeEntry = set.ActiveKey;
        var descriptor = activeEntry.Descriptor;
        var privateKey = set.GetPrivateKey(activeEntry.Index);

        var headerJson = BuildHeaderJson(descriptor.Algorithm, descriptor.Kid);
        var headerBytes = Encoding.UTF8.GetBytes(headerJson);
        var headerSegment = Base64UrlEncode(headerBytes);

        // Form the signing input: base64url(header) + "." + base64url(payload)
        var headerStr = Encoding.ASCII.GetString(headerSegment.Span);
        var payloadStr = Encoding.ASCII.GetString(payloadSegment.Span);
        var signingInput = Encoding.UTF8.GetBytes($"{headerStr}.{payloadStr}");

        var signatureBytes = Sign(privateKey, descriptor.Algorithm, signingInput);
        var signatureSegment = Base64UrlEncode(signatureBytes);

        return new SigningResult(headerSegment, signatureSegment, descriptor.Kid, descriptor.Algorithm);
    }

    [ExcludeFromCodeCoverage(Justification = "Unreachable default arm — all SigningAlgorithm members are handled above.")]
    private static ReadOnlyMemory<byte> Sign(
        System.Security.Cryptography.AsymmetricAlgorithm privateKey,
        SigningAlgorithm algorithm,
        byte[] signingInput)
    {
        return algorithm switch
        {
            SigningAlgorithm.RS256 => SignRsa((RSA)privateKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1, signingInput),
            SigningAlgorithm.RS384 => SignRsa((RSA)privateKey, HashAlgorithmName.SHA384, RSASignaturePadding.Pkcs1, signingInput),
            SigningAlgorithm.RS512 => SignRsa((RSA)privateKey, HashAlgorithmName.SHA512, RSASignaturePadding.Pkcs1, signingInput),
            SigningAlgorithm.PS256 => SignRsa((RSA)privateKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pss, signingInput),
            SigningAlgorithm.PS384 => SignRsa((RSA)privateKey, HashAlgorithmName.SHA384, RSASignaturePadding.Pss, signingInput),
            SigningAlgorithm.PS512 => SignRsa((RSA)privateKey, HashAlgorithmName.SHA512, RSASignaturePadding.Pss, signingInput),
            SigningAlgorithm.ES256 => SignEc((ECDsa)privateKey, HashAlgorithmName.SHA256, signingInput),
            SigningAlgorithm.ES384 => SignEc((ECDsa)privateKey, HashAlgorithmName.SHA384, signingInput),
            SigningAlgorithm.ES512 => SignEc((ECDsa)privateKey, HashAlgorithmName.SHA512, signingInput),
            _ => ThrowUnsupportedAlgorithm<ReadOnlyMemory<byte>>(algorithm),
        };
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static byte[] SignRsa(RSA rsa, HashAlgorithmName hash, RSASignaturePadding padding, byte[] input)
        => rsa.SignData(input, hash, padding);

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static byte[] SignEc(ECDsa ec, HashAlgorithmName hash, byte[] input)
        // RFC 7518 §3.4 requires the IEEE P1363 format (raw R||S concatenation).
        // Rfc3279DerSequence (DER) is the wrong format and will fail on all standards-compliant RPs.
        => ec.SignData(input, hash, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);

    [ExcludeFromCodeCoverage(Justification = "Unreachable default arm — all SigningAlgorithm members are handled above.")]
    private static string BuildHeaderJson(SigningAlgorithm algorithm, string kid)
    {
        var algStr = algorithm switch
        {
            SigningAlgorithm.RS256 => "RS256",
            SigningAlgorithm.RS384 => "RS384",
            SigningAlgorithm.RS512 => "RS512",
            SigningAlgorithm.PS256 => "PS256",
            SigningAlgorithm.PS384 => "PS384",
            SigningAlgorithm.PS512 => "PS512",
            SigningAlgorithm.ES256 => "ES256",
            SigningAlgorithm.ES384 => "ES384",
            SigningAlgorithm.ES512 => "ES512",
            _ => ThrowUnsupportedAlgorithm<string>(algorithm),
        };

        // Minimal JWS header: {"alg":"…","kid":"…"}
        return $"{{\"alg\":\"{algStr}\",\"kid\":\"{JsonEncodedText.Encode(kid)}\"}}";
    }

    private static ReadOnlyMemory<byte> Base64UrlEncode(ReadOnlyMemory<byte> input)
    {
        var span = input.Span;
        var encoded = new byte[Base64Url.GetEncodedLength(span.Length)];
        Base64Url.EncodeToUtf8(span, encoded);
        return encoded;
    }

    private static ReadOnlyMemory<byte> Base64UrlEncode(byte[] input)
    {
        var encoded = new byte[Base64Url.GetEncodedLength(input.Length)];
        Base64Url.EncodeToUtf8(input, encoded);
        return encoded;
    }

    private static void ValidateKeySet(SigningKeySet set)
    {
        var seenKids = new HashSet<string>(StringComparer.Ordinal);

        for (var i = 0; i < set.Keys.Count; i++)
        {
            var entry = set.Keys[i];
            var descriptor = entry.Descriptor;

            if (!seenKids.Add(descriptor.Kid))
            {
                throw new ZeeKayDaConfigurationException(
                    new ZeeKayDaConfigurationFailure(
                        "signing.duplicate_kid",
                        $"The signing key set contains duplicate kid '{descriptor.Kid}'. " +
                        "Each key must have a unique, stable identifier."));
            }

            ValidateKeyAlgorithmCompatibility(descriptor, set.GetPrivateKey(i));
            ValidateKeyStrength(descriptor);
        }
    }

    private static void ValidateKeyStrength(SigningKeyDescriptor descriptor)
    {
        if (descriptor.KeyType == SigningKeyType.Rsa)
        {
            var modulus = descriptor.RsaPublicParameters!.Value.Modulus;
            var bitLength = modulus is not null ? modulus.Length * 8 : 0;

            if (bitLength < 2048)
            {
                throw new ZeeKayDaConfigurationException(
                    new ZeeKayDaConfigurationFailure(
                        "signing.rsa_key_too_small",
                        $"RSA key '{descriptor.Kid}' is {bitLength} bits. " +
                        "Minimum key size is 2048 bits per NIST SP 800-57."));
            }
        }
        else if (descriptor.KeyType == SigningKeyType.Ec)
        {
            var ecParams = descriptor.EcPublicParameters!.Value;
            var curveOid = ecParams.Curve.Oid?.Value;

            if (!AcceptedEcCurveOids.Contains(curveOid ?? string.Empty))
            {
                throw new ZeeKayDaConfigurationException(
                    new ZeeKayDaConfigurationFailure(
                        "signing.ec_unsupported_curve",
                        $"EC key '{descriptor.Kid}' uses curve OID '{curveOid ?? "unknown"}'. " +
                        "Only NIST P-256, P-384, and P-521 are accepted."));
            }
        }
    }

    private static void ValidateKeyAlgorithmCompatibility(
        SigningKeyDescriptor descriptor,
        System.Security.Cryptography.AsymmetricAlgorithm privateKey)
    {
        var isRsaAlgorithm = descriptor.Algorithm is
            SigningAlgorithm.RS256 or SigningAlgorithm.RS384 or SigningAlgorithm.RS512
            or SigningAlgorithm.PS256 or SigningAlgorithm.PS384 or SigningAlgorithm.PS512;

        var isEcAlgorithm = descriptor.Algorithm is
            SigningAlgorithm.ES256 or SigningAlgorithm.ES384 or SigningAlgorithm.ES512;

        if (isRsaAlgorithm && privateKey is not RSA)
        {
            throw new ZeeKayDaConfigurationException(
                new ZeeKayDaConfigurationFailure(
                    "signing.key_algorithm_mismatch",
                    $"Key '{descriptor.Kid}' claims RSA algorithm {descriptor.Algorithm} but the private key is not an RSA key."));
        }

        if (isEcAlgorithm && privateKey is not ECDsa)
        {
            throw new ZeeKayDaConfigurationException(
                new ZeeKayDaConfigurationFailure(
                    "signing.key_algorithm_mismatch",
                    $"Key '{descriptor.Kid}' claims EC algorithm {descriptor.Algorithm} but the private key is not an ECDsa key."));
        }

        // Validate EC curve ↔ algorithm pairing
        if (isEcAlgorithm && privateKey is ECDsa ecKey)
        {
            var ecParams = ecKey.ExportParameters(false);
            var curveOid = ecParams.Curve.Oid?.Value ?? string.Empty;

            AlgorithmCurveOids.TryGetValue(descriptor.Algorithm, out var expectedOid);

            if (expectedOid is null || !string.Equals(expectedOid, curveOid, StringComparison.OrdinalIgnoreCase))
            {
                throw new ZeeKayDaConfigurationException(
                    new ZeeKayDaConfigurationFailure(
                        "signing.ec_curve_algorithm_mismatch",
                        $"Key '{descriptor.Kid}' uses algorithm {descriptor.Algorithm} which requires " +
                        $"curve OID {expectedOid ?? descriptor.Algorithm.ToString()}, but the key uses curve OID '{curveOid}'."));
            }
        }
    }

    /// <summary>
    /// Unreachable defensive guard for switch statements that are exhaustive over
    /// <see cref="SigningAlgorithm"/>. Throws <see cref="NotSupportedException"/>.
    /// </summary>
    [ExcludeFromCodeCoverage(Justification = "Unreachable defensive guard — all enum members are handled in callers.")]
    [DoesNotReturn]
    private static T ThrowUnsupportedAlgorithm<T>(SigningAlgorithm algorithm)
        => throw new NotSupportedException($"Signing algorithm {algorithm} is not supported.");
}
