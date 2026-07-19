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
    // null = static-source mode: LoadKeysAsync is invoked at most once and the cache never expires.
    private readonly TimeSpan? _keySourceRefreshInterval;

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
        _keySourceRefreshInterval = options.Value.KeySourceRefreshInterval;
    }

    /// <summary>
    /// Loads the current set of trusted signing keys. Called by the base class at most once
    /// per <see cref="JwtSigningServiceOptions.KeySourceRefreshInterval"/>; concurrent callers after
    /// the interval elapses are coalesced into a single load via the single-flight gate. When
    /// <see cref="JwtSigningServiceOptions.KeySourceRefreshInterval"/> is <see langword="null"/>
    /// (static-source mode), this method is called at most once for the lifetime of the service.
    /// </summary>
    /// <param name="cancellationToken">A token to cancel the operation.</param>
    /// <returns>
    /// The trusted key set. The first entry is the active signing key. Must never be empty.
    /// </returns>
    /// <remarks>
    /// Every call MUST return a genuinely new <see cref="SigningKeySet"/> instance; this method
    /// MUST NOT return the same instance twice (for example a memoised set held to signal
    /// "unchanged" — use <see cref="HasKeySetChangedAsync"/> for that instead). This is enforced at
    /// runtime, not just documented — but only for the naive case: the base class compares the
    /// returned instance against the previously cached set by reference immediately after this
    /// method returns, and throws an <see cref="InvalidOperationException"/> right away if they are
    /// the same object — before the previous set is disposed or the new one is installed as
    /// current. This is a reference-equality tripwire, not a deep check: building a genuinely new
    /// <see cref="SigningKeySet"/> that nonetheless wraps the same underlying key objects as the
    /// previous set is still this method's responsibility to avoid, and would reproduce the same
    /// failure the guard exists to catch. Without either guard, the returned set's private-key
    /// objects are owned by the base class: immediately after installing a freshly loaded set as
    /// current, the base class unconditionally <c>Dispose()</c>s the superseded reference, so
    /// returning the same instance (or the same underlying keys via a new wrapper) would dispose
    /// objects still referenced by the current set, and the next <c>GetPrivateKey</c> call on it
    /// would throw a confusing, disconnected <see cref="ObjectDisposedException"/> instead. See ADR
    /// 0011 §3.2.
    /// </remarks>
    protected abstract ValueTask<SigningKeySet> LoadKeysAsync(CancellationToken cancellationToken);

    /// <summary>
    /// Asked once per refresh cycle, after <see cref="JwtSigningServiceOptions.KeySourceRefreshInterval"/>
    /// elapses and only when a previous key set already exists, whether the trusted key set has
    /// actually changed since the last successful <see cref="LoadKeysAsync"/> call.
    /// </summary>
    /// <param name="cancellationToken">A token to cancel the operation.</param>
    /// <returns>
    /// <see langword="false"/> to keep serving the existing cached set for another interval
    /// without calling <see cref="LoadKeysAsync"/> — skipping an expensive key-material reload
    /// when nothing has rotated. <see langword="true"/> (the default) to proceed with a normal
    /// <see cref="LoadKeysAsync"/> refresh, exactly as if this method did not exist.
    /// </returns>
    /// <remarks>
    /// This is the "ask" step described in ADR 0011 §3.2, in front of the "refresh." The default
    /// implementation always returns <see langword="true"/>, so every provider that does not
    /// override this method keeps today's unconditional-rebuild behaviour unchanged. It is never
    /// consulted for the first load — a cold start (no previous set) always calls
    /// <see cref="LoadKeysAsync"/> directly. A provider overriding this method should perform only
    /// a cheap, metadata-only check (e.g. re-enumerating version metadata without downloading key
    /// material); anything expensive enough to want to skip belongs in <see cref="LoadKeysAsync"/>
    /// itself, not here.
    /// <para>
    /// Returning <see langword="false"/> from this method is the correct, supported way to report
    /// "nothing has changed since the last cycle." Naively achieving the same effect by having
    /// <see cref="LoadKeysAsync"/> return the same <see cref="SigningKeySet"/> instance it returned
    /// last time — instead of overriding this method — is not supported and no longer fails
    /// confusingly later: the base class now detects that reference-equality violation immediately
    /// after <see cref="LoadKeysAsync"/> returns and throws an <see cref="InvalidOperationException"/>
    /// on the spot, rather than disposing the set and only surfacing the mistake as a disconnected
    /// <see cref="ObjectDisposedException"/> from a later <c>GetPrivateKey</c> call.
    /// </para>
    /// <para>
    /// An override throwing is <b>fail-closed by design</b>. The base class awaits this method with
    /// no fallback: if it throws, the exception propagates straight out to the current caller (the
    /// in-flight <see cref="GetSigningKeysAsync"/> / <see cref="SignAsync"/> fails) and the cached
    /// set and its expiry are left untouched — there is no stale-cache fallback and the exception is
    /// never swallowed. This is deliberately the exact same failure shape as <see cref="LoadKeysAsync"/>
    /// throwing, which also propagates directly with no fallback. Do not invent divergent fail-soft
    /// behaviour (swallow-and-treat-as-unchanged, or swallow-and-continue-serving-the-stale-set): a
    /// silent fallback would mask an operational check failing, which is exactly what fail-closed
    /// exists to prevent. See ADR 0011 §3.2.
    /// </para>
    /// </remarks>
    protected virtual ValueTask<bool> HasKeySetChangedAsync(CancellationToken cancellationToken) => new(true);

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

            // The "ask" step (ADR 0011 §3.2): when a previous set already exists, give the
            // implementor a chance to report "nothing has changed" cheaply, without paying for a
            // full LoadKeysAsync reload. Never consulted on a cold start (previous is null) — a
            // cold start always loads.
            if (previous is not null && !await HasKeySetChangedAsync(cancellationToken).ConfigureAwait(false))
            {
                // Unchanged: extend the expiry and keep serving the existing set. LoadKeysAsync is
                // not invoked, and nothing is swapped or disposed.
                _cacheExpiresAt = ComputeNextCacheExpiry();

                // Inside the lock the set cannot be concurrently disposed, so TryBorrow is
                // guaranteed to succeed here.
                previous.TryBorrow();
                return previous;
            }

            var newSet = await LoadKeysAsync(cancellationToken).ConfigureAwait(false);

            // Enforce the "always a new instance" contract immediately, before anything is
            // validated, disposed, or installed as current. Failing here — rather than letting
            // the stale instance get disposed and re-installed — means the previous cached set is
            // left completely intact: this call fails loudly, but the service keeps serving the
            // last known good set to any other caller, and a subsequent call can still succeed if
            // the implementor does not hit this every time.
            if (previous is not null && ReferenceEquals(newSet, previous))
            {
                throw new InvalidOperationException(
                    $"{GetType().Name}.LoadKeysAsync returned the same SigningKeySet instance as " +
                    "the previously cached set. LoadKeysAsync must always return a new instance on " +
                    "every call; to report that nothing has changed since the last cycle, override " +
                    "HasKeySetChangedAsync to return false instead.");
            }

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
            _cacheExpiresAt = ComputeNextCacheExpiry();

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
    /// Computes the cache's next expiry instant from the current time, applied identically whether
    /// the cache is being extended (the "ask" reported no change) or replaced (a fresh
    /// <see cref="LoadKeysAsync"/> result was just installed).
    /// </summary>
    private DateTimeOffset ComputeNextCacheExpiry() =>
        // null means static-source mode (see JwtSigningServiceOptions.KeySourceRefreshInterval):
        // the cache never expires. HasKeySetChangedAsync is realistically never reached in this
        // mode, since the cache never expires and BorrowSetAsync's slow path is therefore never
        // re-entered after the first load — this branch exists only as a defensive fallback.
        _keySourceRefreshInterval is { } interval
            ? _timeProvider.GetUtcNow().Add(interval)
            : DateTimeOffset.MaxValue;

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
        var privateKey = set.GetActivePrivateKey();

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
