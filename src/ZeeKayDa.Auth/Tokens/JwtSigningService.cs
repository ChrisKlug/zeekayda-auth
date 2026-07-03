using System.Buffers;
using System.Buffers.Text;
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
    private readonly TimeProvider _timeProvider;
    private readonly TimeSpan _refreshInterval;

    // Single-flight refresh gate: null means "no refresh in flight or cache valid".
    private readonly SemaphoreSlim _refreshLock = new(1, 1);
    private SigningKeySet? _cachedSet;
    private DateTimeOffset _cacheExpiresAt = DateTimeOffset.MinValue;
    // 0 = live, 1 = disposed. int so Interlocked.Exchange makes the transition atomic.
    private int _disposeState;

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
        // Borrow the set for the duration of the read; descriptors are safe to access
        // without holding the lock once we hold a borrow.
        var set = await BorrowSetAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            return set.Keys;
        }
        finally
        {
            set.Return();
        }
    }

    /// <inheritdoc/>
    public async ValueTask<SigningResult> SignAsync(
        ReadOnlyMemory<byte> payloadSegment,
        CancellationToken cancellationToken = default)
    {
        // Borrow the set for the duration of the signing operation so that a concurrent
        // DisposeAsync cannot release the private key objects while we are using them.
        var set = await BorrowSetAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            return await PerformSignAsync(set, payloadSegment, cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            set.Return();
        }
    }

    /// <summary>
    /// Produces the signature bytes for <paramref name="signingInput"/> using
    /// <paramref name="activeKey"/>. The default implementation signs locally and synchronously
    /// via <see cref="SigningAlgorithms.Sign"/>.
    /// </summary>
    /// <param name="activeKey">
    /// The active signing key, exactly as selected and validated by the base class. Header
    /// construction, active-key selection, and <c>kid</c>/<c>alg</c> assignment always happen in
    /// the non-overridable caller of this method, so the header is guaranteed to match the key
    /// used here — overriding this method cannot desynchronise the two.
    /// </param>
    /// <param name="signingInput">
    /// The exact bytes to sign: <c>base64url(header) + '.' + base64url(payload)</c>.
    /// </param>
    /// <param name="cancellationToken">A token to cancel the operation.</param>
    /// <returns>The raw signature bytes in the format required by <c>activeKey.Descriptor.Algorithm</c>.</returns>
    /// <remarks>
    /// Override this method to perform signing remotely (e.g. a cloud KMS or HSM API) instead of
    /// with a local, in-process private key. Remote overrides typically ignore
    /// <see cref="SigningKeyPair.PrivateKey"/> on <paramref name="activeKey"/> entirely — the
    /// descriptor is still needed to select the correct remote key and algorithm. There is no way
    /// in C# to omit that unused member from the signature without adding an allocation-costing
    /// indirection layer for no functional benefit, so it is documented as intentionally unused
    /// by remote overrides rather than removed.
    /// </remarks>
    protected virtual ValueTask<ReadOnlyMemory<byte>> SignInputAsync(
        SigningKeyPair activeKey, byte[] signingInput, CancellationToken cancellationToken)
        => new(SigningAlgorithms.Sign(activeKey.Descriptor, signingInput, activeKey.PrivateKey));

    /// <inheritdoc/>
    public async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref _disposeState, 1) != 0)
            return;

        await _refreshLock.WaitAsync().ConfigureAwait(false);
        try
        {
            var set = _cachedSet;
            _cachedSet = null;

            // Dispose releases the cache's borrow. Private keys are freed only once all
            // in-flight borrows (from the fast path) have also called Return().
            set?.Dispose();
        }
        finally
        {
            _refreshLock.Release();
        }

        _refreshLock.Dispose();
        GC.SuppressFinalize(this);
    }

    /// <summary>
    /// Returns the current (or freshly loaded) key set with a borrow already acquired.
    /// The caller MUST call <see cref="SigningKeySet.Return"/> exactly once when done.
    /// </summary>
    private async ValueTask<SigningKeySet> BorrowSetAsync(CancellationToken cancellationToken)
    {
        var now = _timeProvider.GetUtcNow();

        // Fast path: cache is still valid — try to borrow without acquiring the lock.
        // TryBorrow fails only if DisposeAsync has already zeroed the refcount, in which
        // case we fall through to the slow path.
        var current = Volatile.Read(ref _cachedSet);
        if (current is not null && now < _cacheExpiresAt && current.TryBorrow())
            return current;

        // Cache is cold, expired, or being disposed: single-flight gate.
        await _refreshLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            // Re-check inside the lock; another caller may have refreshed while we waited.
            now = _timeProvider.GetUtcNow();
            if (_cachedSet is not null && now < _cacheExpiresAt)
            {
                // Inside the lock the set cannot be concurrently disposed, so TryBorrow
                // is guaranteed to succeed here.
                _cachedSet.TryBorrow();
                return _cachedSet;
            }

            var previous = _cachedSet;
            var newSet = await LoadKeysAsync(cancellationToken).ConfigureAwait(false);

            try
            {
                ValidateKeySet(newSet);
            }
            catch
            {
                newSet.Dispose();
                throw;
            }

            _cachedSet = newSet;

            // Guard against overflow when RefreshInterval is effectively infinite
            // (e.g. TimeSpan.MaxValue set by DevelopmentSigningKeyOptions).
            _cacheExpiresAt = _refreshInterval == TimeSpan.MaxValue
                ? DateTimeOffset.MaxValue
                : _timeProvider.GetUtcNow().Add(_refreshInterval);

            // Release the cache's borrow on the old set. Its private keys are freed once
            // any in-flight fast-path borrows that still hold a reference have also returned.
            previous?.Dispose();

            // Acquire a borrow for the caller before releasing the lock.
            newSet.TryBorrow();
            return newSet;
        }
        finally
        {
            _refreshLock.Release();
        }
    }

    /// <summary>
    /// Builds the JWS header and signing input for the active key and dispatches to
    /// <see cref="SignInputAsync"/> for the actual cryptographic operation.
    /// </summary>
    /// <remarks>
    /// This method is deliberately non-virtual: header construction, active-key selection, and
    /// <c>kid</c>/<c>alg</c> assignment must always be consistent with whichever key actually
    /// signs the input, so only the cryptographic step itself (<see cref="SignInputAsync"/>) is
    /// overridable.
    /// </remarks>
    private async ValueTask<SigningResult> PerformSignAsync(
        SigningKeySet set, ReadOnlyMemory<byte> payloadSegment, CancellationToken cancellationToken)
    {
        var descriptor = set.ActiveKey;
        var privateKey = set.GetPrivateKey(0);

        var headerBytes = BuildHeaderJsonBytes(descriptor.Algorithm, descriptor.Kid);
        var headerSegment = Base64UrlEncode(headerBytes);

        // Assemble the signing input: base64url(header) + 0x2E + base64url(payload).
        // Written directly into a single buffer to avoid intermediate string allocations.
        var signingInput = AssembleSigningInput(headerSegment, payloadSegment);

        var activeKey = new SigningKeyPair { Descriptor = descriptor, PrivateKey = privateKey };
        var signatureBytes = await SignInputAsync(activeKey, signingInput, cancellationToken).ConfigureAwait(false);
        var signatureSegment = Base64UrlEncode(signatureBytes);

        return new SigningResult(headerSegment, signatureSegment, descriptor.Kid, descriptor.Algorithm);
    }

    /// <summary>
    /// Writes the JWS header <c>{"alg":"&lt;algorithm&gt;","kid":"&lt;kid&gt;","typ":"JWT"}</c>
    /// as UTF-8 bytes using <see cref="Utf8JsonWriter"/> — no intermediate string allocation.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <see cref="SigningAlgorithm"/> enum member names match the RFC 7518 string identifiers
    /// exactly (RS256, ES256, etc.), so <c>algorithm.ToString()</c> produces the correct
    /// <c>alg</c> header value without a switch statement.
    /// </para>
    /// <para>
    /// <c>typ</c> is always set to <c>"JWT"</c> per RFC 7519 §5.1 and RFC 8725 §3.11. It is
    /// written here rather than by the caller so that every token produced by this service
    /// carries it automatically — a caller that omits it would produce a non-compliant token.
    /// </para>
    /// </remarks>
    private static ReadOnlyMemory<byte> BuildHeaderJsonBytes(SigningAlgorithm algorithm, string kid)
    {
        var buffer = new ArrayBufferWriter<byte>();
        using var writer = new Utf8JsonWriter(buffer, new JsonWriterOptions { Indented = false });

        writer.WriteStartObject();
        writer.WriteString("alg", algorithm.ToString());
        writer.WriteString("kid", JsonEncodedText.Encode(kid));
        writer.WriteString("typ", "JWT");
        writer.WriteEndObject();

        writer.Flush();
        return buffer.WrittenMemory;
    }

    /// <summary>
    /// Assembles the JWS signing input <c>base64url(header).base64url(payload)</c> into a
    /// single byte array without going through an intermediate string.
    /// </summary>
    private static byte[] AssembleSigningInput(
        ReadOnlyMemory<byte> headerSegment,
        ReadOnlyMemory<byte> payloadSegment)
    {
        // header.Length + 1 (for '.') + payload.Length
        var result = new byte[headerSegment.Length + 1 + payloadSegment.Length];
        headerSegment.Span.CopyTo(result);
        result[headerSegment.Length] = (byte)'.';
        payloadSegment.Span.CopyTo(result.AsSpan(headerSegment.Length + 1));
        return result;
    }

    private static ReadOnlyMemory<byte> Base64UrlEncode(ReadOnlyMemory<byte> input)
    {
        var span = input.Span;
        var encoded = new byte[Base64Url.GetEncodedLength(span.Length)];
        Base64Url.EncodeToUtf8(span, encoded);
        return encoded;
    }

    private static void ValidateKeySet(SigningKeySet set)
    {
        var seenKids = new HashSet<string>(StringComparer.Ordinal);

        for (var i = 0; i < set.Keys.Count; i++)
        {
            var descriptor = set.Keys[i];

            if (!seenKids.Add(descriptor.Kid))
            {
                throw new ZeeKayDaConfigurationException(
                    new ZeeKayDaConfigurationFailure(
                        "signing.duplicate_kid",
                        $"The signing key set contains duplicate kid '{descriptor.Kid}'. " +
                        "Each key must have a unique, stable identifier."));
            }

            SigningAlgorithms.ValidateKeyAlgorithmCompatibility(descriptor, set.GetPrivateKey(i));
            SigningAlgorithms.ValidateKeyStrength(descriptor);
        }
    }
}
