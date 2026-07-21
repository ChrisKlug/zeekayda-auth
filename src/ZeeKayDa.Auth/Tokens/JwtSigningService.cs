using System.Buffers;
using System.Buffers.Text;
using System.Linq;
using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using ZeeKayDa.Auth.Logging;

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
    // null = static-source mode (TOptions derives from StaticKeySourceOptions): LoadKeysAsync is
    // invoked at most once and the cache never expires.
    private readonly TimeSpan? _keyRotationCheckInterval;

    // Single-flight refresh gate: null means "no refresh in flight or cache valid".
    private readonly SemaphoreSlim _refreshLock = new(1, 1);
    private SigningKeySet? _cachedSet;
    private DateTimeOffset _cacheExpiresAt = DateTimeOffset.MinValue;
    // 0 = live, 1 = disposed. int so Interlocked.Exchange makes the transition atomic.
    private int _disposeState;

    // ── KeySetOptions/KeySourceOptions state ────────────────────────────────────────────────────────
    // Lands alongside the ADR 0011 fields above (issue #420 is additive-only). Which set of fields is
    // actually used is decided once, at construction, from which options tier TOptions's runtime
    // instance derives from.
    private readonly KeyRetrievalMode _retrievalMode;
    private readonly IOptions<TOptions> _options;
    private readonly TimeSpan? _refreshInterval; // Tier B (KeySourceOptions) only.
    private readonly ISigningKeyRetirementWindowProvider? _retirementWindowProvider;
    private readonly ISanitizingLogger<JwtSigningService<TOptions>>? _logger;

    private readonly SemaphoreSlim _snapshotLock = new(1, 1);
    private readonly SemaphoreSlim _signerLock = new(1, 1);
    private SigningKeySnapshot? _snapshot;
    private DateTimeOffset _snapshotExpiresAt = DateTimeOffset.MinValue;
    private SignerHandle? _activeSignerHandle;

    /// <summary>
    /// Initialises the base class with options and a time provider.
    /// </summary>
    /// <param name="options">The provider-specific options.</param>
    /// <param name="timeProvider">
    /// The time provider used for cache-expiry calculations. Inject <see cref="TimeProvider"/>
    /// from DI or use <c>TimeProvider.System</c> in production and a
    /// <c>FakeTimeProvider</c> in tests.
    /// </param>
    /// <exception cref="NotSupportedException">
    /// <c>TOptions</c>'s runtime instance derives from <see cref="KeySetOptions"/> or
    /// <see cref="KeySourceOptions"/> (the ADR 0015 contract). Use the four-argument overload for
    /// those instead — constructing this class via this overload for a KeySetOptions/KeySourceOptions
    /// <c>TOptions</c> would otherwise silently default the retirement window to
    /// <see cref="TimeSpan.Zero"/> and drop the logger, degrading the ADR 0015 §6
    /// within-window-vanish <see cref="Microsoft.Extensions.Logging.LogLevel.Warning"/> — a signal
    /// that MUST NOT be downgraded — into silence.
    /// </exception>
    /// <remarks>
    /// Use this overload only for a provider on the ADR 0011 contract (deriving <c>TOptions</c>
    /// from <see cref="StaticKeySourceOptions"/> or <see cref="RotatingKeySourceOptions"/> and
    /// overriding <see cref="LoadKeysAsync"/>). A provider on the ADR 0015 contract (deriving
    /// <c>TOptions</c> from <see cref="KeySetOptions"/> or <see cref="KeySourceOptions"/> and
    /// overriding <see cref="ListKeysAsync"/>/<see cref="CreateSignerAsync"/>) MUST use the other
    /// constructor overload instead, which also supplies the retirement-window provider and logger
    /// the KeySetOptions/KeySourceOptions contract's kill-by-omission and JWKS-inclusion logic needs; this overload throws
    /// rather than silently accepting a KeySetOptions/KeySourceOptions <c>TOptions</c>.
    /// </remarks>
    protected JwtSigningService(IOptions<TOptions> options, TimeProvider timeProvider)
    {
        (_retrievalMode, _timeProvider, _keyRotationCheckInterval, _refreshInterval) =
            ResolveSharedState(options, timeProvider);
        _options = options;

        if (_retrievalMode != KeyRetrievalMode.Legacy)
        {
            throw new NotSupportedException(
                $"{GetType().Name} derives its options from {nameof(KeySetOptions)}/{nameof(KeySourceOptions)} " +
                "(the ADR 0015 contract) but was constructed with the two-argument JwtSigningService " +
                "constructor. Use the four-argument overload instead, which also supplies the " +
                $"{nameof(ISigningKeyRetirementWindowProvider)} and {nameof(ISanitizingLogger<JwtSigningService<TOptions>>)} " +
                "the KeySetOptions/KeySourceOptions contract's kill-by-omission and JWKS-inclusion logic needs — constructing this " +
                "class via the two-argument overload would otherwise silently degrade the ADR 0015 §6 " +
                "within-window-vanish Warning (a signal that MUST NOT be downgraded) by defaulting the " +
                "retirement window to TimeSpan.Zero and dropping the logger.");
        }
    }

    /// <summary>
    /// Initialises the base class for a provider on the ADR 0015 contract (<see cref="KeySetOptions"/>
    /// or <see cref="KeySourceOptions"/>).
    /// </summary>
    /// <param name="options">The provider-specific options.</param>
    /// <param name="timeProvider">
    /// The time provider used for cache-expiry and activation-timeline calculations.
    /// </param>
    /// <param name="retirementWindowProvider">
    /// Supplies the derived retirement window (ADR 0011 §3.3) used to compute which keys are
    /// currently included in the JWKS, and to disambiguate a kill-by-omission vanish as
    /// within-window versus post-window (ADR 0015 §6).
    /// </param>
    /// <param name="logger">
    /// Used to emit the <see cref="Microsoft.Extensions.Logging.LogLevel.Warning"/> required by
    /// ADR 0015 §6 when a Tier B provider's key listing drops a key while it is still inside its
    /// retirement window.
    /// </param>
    protected JwtSigningService(
        IOptions<TOptions> options,
        TimeProvider timeProvider,
        ISigningKeyRetirementWindowProvider retirementWindowProvider,
        ISanitizingLogger<JwtSigningService<TOptions>> logger)
    {
        ArgumentNullException.ThrowIfNull(retirementWindowProvider);
        ArgumentNullException.ThrowIfNull(logger);

        (_retrievalMode, _timeProvider, _keyRotationCheckInterval, _refreshInterval) =
            ResolveSharedState(options, timeProvider);
        _options = options;
        _retirementWindowProvider = retirementWindowProvider;
        _logger = logger;
    }

    /// <summary>
    /// Loads the current set of trusted signing keys. For rotating-tier providers
    /// (<see cref="RotatingKeySourceOptions"/>), called by the base class at most once per
    /// <see cref="RotatingKeySourceOptions.KeyRotationCheckInterval"/>; concurrent callers after
    /// the interval elapses are coalesced into a single load via the single-flight gate. For
    /// static-tier providers (<see cref="StaticKeySourceOptions"/>), this method is called at most
    /// once for the lifetime of the service.
    /// </summary>
    /// <param name="cancellationToken">A token to cancel the operation.</param>
    /// <returns>
    /// The trusted key set. The first entry is the active signing key. Must never be empty.
    /// </returns>
    /// <remarks>
    /// Every call MUST return a genuinely new <see cref="SigningKeySet"/> instance, and that new
    /// instance MUST wrap genuinely new private-key objects — reusing the underlying key material
    /// of a previously returned set is not permitted even when it is wrapped in a new
    /// <see cref="SigningKeySet"/> (for example a memoised set held to signal "unchanged" — use
    /// <see cref="HasKeySetChangedAsync"/> for that instead). Both failure modes are enforced at
    /// runtime, not just documented, immediately after this method returns and before the previous
    /// set is disposed or the new one is installed as current:
    /// <list type="bullet">
    /// <item>
    /// <description>
    /// <b>Same instance:</b> the base class compares the returned instance against the previously
    /// cached set by reference and throws an <see cref="InvalidOperationException"/> right away if
    /// they are the same object.
    /// </description>
    /// </item>
    /// <item>
    /// <description>
    /// <b>Same private key under a shared kid:</b> for every <c>kid</c> present in both the new and
    /// previous set, the base class also compares the two sets' private-key objects by reference and
    /// throws an <see cref="InvalidOperationException"/> if any pair is the same object — even though
    /// the enclosing <see cref="SigningKeySet"/> instance is genuinely new. Without this check, the
    /// failure would surface later and much less clearly, as a confusing, disconnected
    /// <see cref="ObjectDisposedException"/> once the previous set is disposed below.
    /// </description>
    /// </item>
    /// </list>
    /// Neither guard is a full deep-equality check of the whole key set: they do not compare public
    /// key material, algorithm metadata, or keys whose <c>kid</c> does not also appear in the
    /// previous set. They only catch instance reuse and reused private-key objects under a shared
    /// <c>kid</c> — the two ways a naive or partially-naive <see cref="LoadKeysAsync"/> override can
    /// accidentally hand ownership of live key material to two sets at once. Without either guard,
    /// the returned set's private-key objects are owned by the base class: immediately after
    /// installing a freshly loaded set as current, the base class unconditionally <c>Dispose()</c>s
    /// the superseded reference, so returning the same instance (or the same underlying keys via a
    /// new wrapper) would dispose objects still referenced by the current set. See ADR 0011 §3.2.
    /// <para>
    /// This is only ever called on a provider whose <c>TOptions</c> derives from
    /// <see cref="StaticKeySourceOptions"/> or <see cref="RotatingKeySourceOptions"/> (the ADR 0011
    /// contract). Not abstract — virtual with a default that throws
    /// <see cref="NotSupportedException"/> — so that a provider on the ADR 0015 contract (deriving
    /// <c>TOptions</c> from <see cref="KeySetOptions"/>/<see cref="KeySourceOptions"/> and
    /// overriding <see cref="ListKeysAsync"/>/<see cref="CreateSignerAsync"/> instead) is not forced
    /// to implement this unused method (issue #420 is additive-only: the two contracts coexist on
    /// this base class until every provider has migrated — issue #428).
    /// </para>
    /// </remarks>
    protected virtual ValueTask<SigningKeySet> LoadKeysAsync(CancellationToken cancellationToken) =>
        throw new NotSupportedException(
            $"{GetType().Name} derives its options from {nameof(StaticKeySourceOptions)}/{nameof(RotatingKeySourceOptions)} " +
            $"but does not override {nameof(LoadKeysAsync)}.");

    /// <summary>
    /// Asked once per refresh cycle, after <see cref="RotatingKeySourceOptions.KeyRotationCheckInterval"/>
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

    /// <summary>
    /// Returns the current listing of trusted signing keys as pure public metadata — never private
    /// material. Tier A (<see cref="KeySetOptions"/>) providers: called exactly once, ever. Tier B
    /// (<see cref="KeySourceOptions"/>) providers: called once per <see cref="KeySourceOptions.RefreshInterval"/>.
    /// </summary>
    /// <param name="cancellationToken">A token to cancel the operation.</param>
    /// <returns>Every currently trusted key's public listing. Must never be empty.</returns>
    /// <remarks>
    /// <para>
    /// This method carries a <b>completeness contract</b> (ADR 0015 §6): a provider that cannot
    /// produce a complete read of its current key set <b>MUST throw</b> rather than return a short
    /// or partial list. A vanished key is trusted to mean "no longer trusted" (kill-by-omission);
    /// a failed read must never be indistinguishable from that. The base class never catches or
    /// downgrades an exception from this method — it always propagates straight to the caller,
    /// fail-closed, exactly like <see cref="LoadKeysAsync"/> on the ADR 0011 contract.
    /// </para>
    /// <para>
    /// The base class derives each returned listing's JWKS <c>kid</c> from
    /// <see cref="KeyListing.PublicKey"/> (never from <see cref="KeyListing.Id"/>), rejects a
    /// listing set that yields duplicate <c>kid</c>s, and runs
    /// <see cref="SigningAlgorithms.ValidateKeyAlgorithmCompatibility"/>/<see cref="SigningAlgorithms.ValidateKeyStrength"/>
    /// over every listing — all before <see cref="CreateSignerAsync"/> is ever called for any key
    /// in the set.
    /// </para>
    /// <para>
    /// This is only ever called on a provider whose <c>TOptions</c> derives from
    /// <see cref="KeySetOptions"/> or <see cref="KeySourceOptions"/>. The default implementation
    /// throws <see cref="NotSupportedException"/> so that a provider on the ADR 0015 contract that
    /// forgets to override this fails loudly rather than silently signing with no keys.
    /// </para>
    /// </remarks>
    protected virtual ValueTask<IReadOnlyList<KeyListing>> ListKeysAsync(CancellationToken cancellationToken)
        => throw new NotSupportedException(
            $"{GetType().Name} derives its options from {nameof(KeySetOptions)}/{nameof(KeySourceOptions)} " +
            $"but does not override {nameof(ListKeysAsync)}.");

    /// <summary>
    /// Lends a signer for the key the base class has selected as active. Called only for the
    /// currently active <paramref name="id"/> — never for a non-active, future, or retired key.
    /// The base class owns the returned <see cref="ISigner"/> and disposes it once it is superseded
    /// (see <see cref="ISigner"/>'s <c>Dispose</c> contract).
    /// </summary>
    /// <param name="id">The provider's own identifier for the key to lend a signer for, exactly as
    /// it appeared on one of the <see cref="KeyListing"/>s most recently returned by
    /// <see cref="ListKeysAsync"/>.</param>
    /// <param name="cancellationToken">A token to cancel the operation.</param>
    /// <returns>A signer for the key identified by <paramref name="id"/>.</returns>
    /// <remarks>
    /// Local providers (development, File/PEM, PFX, Windows Certificate Store) build and return a
    /// <see cref="LocalSigner"/> here. A remote provider (Azure Key Vault remote signing, a KMS, an
    /// HSM) returns its own <see cref="ISigner"/> whose <see cref="ISigner.SignAsync"/> makes a
    /// network call — the private key never becomes local. This is only ever called on a provider
    /// whose <c>TOptions</c> derives from <see cref="KeySetOptions"/> or <see cref="KeySourceOptions"/>.
    /// The default implementation throws <see cref="NotSupportedException"/> so that a provider on
    /// the ADR 0015 contract that forgets to override this fails loudly.
    /// </remarks>
    protected virtual ValueTask<ISigner> CreateSignerAsync(KeyId id, CancellationToken cancellationToken)
        => throw new NotSupportedException(
            $"{GetType().Name} derives its options from {nameof(KeySetOptions)}/{nameof(KeySourceOptions)} " +
            $"but does not override {nameof(CreateSignerAsync)}.");

    /// <inheritdoc/>
    public async ValueTask<IReadOnlyList<SigningKeyDescriptor>> GetSigningKeysAsync(
        CancellationToken cancellationToken = default)
    {
        if (_retrievalMode != KeyRetrievalMode.Legacy)
            return await GetSigningKeysAsyncCore(cancellationToken).ConfigureAwait(false);

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
        if (_retrievalMode != KeyRetrievalMode.Legacy)
            return await SignAsyncCore(payloadSegment, cancellationToken).ConfigureAwait(false);

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
    /// via <see cref="SigningAlgorithms.Sign(SigningKeyDescriptor, byte[], AsymmetricAlgorithm)"/>.
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

        await OnDisposeAsync().ConfigureAwait(false);
        await DisposeBaseResourcesAsync().ConfigureAwait(false);

        GC.SuppressFinalize(this);
    }

    /// <summary>
    /// Extension point for a derived provider to release resources <b>it</b> introduced (e.g. a
    /// private key stashed between <see cref="ListKeysAsync"/> and <see cref="CreateSignerAsync"/>
    /// that the base class has no visibility into). The default implementation does nothing.
    /// </summary>
    /// <remarks>
    /// Override this to dispose only resources this specific provider introduced. The base
    /// class's own cleanup always runs regardless of what this override does, or whether it
    /// exists at all — there is no <c>base.OnDisposeAsync()</c> call to remember, unlike a
    /// <c>*Core</c>-suffixed hook. This method is called at most once, guarded by the base
    /// class's own idempotency check in <see cref="DisposeAsync"/>, so an override does not need
    /// its own idempotency guard to be safe under concurrent or repeated <c>DisposeAsync</c> calls.
    /// </remarks>
    protected virtual ValueTask OnDisposeAsync() => ValueTask.CompletedTask;

    /// <summary>
    /// Releases the base class's own resources: the cached <see cref="SigningKeySet"/> (ADR 0011
    /// contract), the ADR 0015 active-signer handle, and the internal locks. Always run by
    /// <see cref="DisposeAsync"/> exactly once, after <see cref="OnDisposeAsync"/> has already
    /// completed — never skippable by a derived class.
    /// </summary>
    private async ValueTask DisposeBaseResourcesAsync()
    {
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

        // ADR 0015 §5: any signer still resident at shutdown (Tier A's opportunistic-disposal
        // worst case, or a Tier B signer between refreshes) is released here.
        await _signerLock.WaitAsync().ConfigureAwait(false);
        try
        {
            _activeSignerHandle?.Release();
            _activeSignerHandle = null;
        }
        finally
        {
            _signerLock.Release();
        }

        _snapshotLock.Dispose();
        _signerLock.Dispose();
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

            // Deeper variant of the same tripwire: a genuinely new SigningKeySet can still wrap one
            // of the previous set's private key objects under a shared kid. previous is not disposed
            // yet at this point (disposal happens further below, after validation and install), so
            // reading its private keys here is safe.
            if (previous is not null && FindReusedPrivateKeyKid(newSet, previous) is { } reusedKid)
            {
                throw new InvalidOperationException(
                    $"{GetType().Name}.LoadKeysAsync returned a new SigningKeySet for kid '{reusedKid}' " +
                    "that wraps the same private key object as the previously cached set. Unlike the " +
                    "same-instance guard, this is a different SigningKeySet instance, but it still " +
                    "shares underlying key material with the set it is meant to replace. LoadKeysAsync " +
                    "must always supply genuinely new private key objects on every call, even when " +
                    "building a new SigningKeySet; to report that nothing has changed since the last " +
                    "cycle, override HasKeySetChangedAsync to return false instead.");
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
        // null means static-source mode (TOptions derives from StaticKeySourceOptions): the cache
        // never expires. HasKeySetChangedAsync is realistically never reached in this mode, since
        // the cache never expires and BorrowSetAsync's slow path is therefore never re-entered
        // after the first load — this branch exists only as a defensive fallback.
        _keyRotationCheckInterval is { } interval
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

    /// <summary>
    /// Finds a <c>kid</c> shared between <paramref name="newSet"/> and <paramref name="previous"/>
    /// whose private key object is the exact same reference in both sets. Returns
    /// <see langword="null"/> if no such <c>kid</c> exists.
    /// </summary>
    private static string? FindReusedPrivateKeyKid(SigningKeySet newSet, SigningKeySet previous)
    {
        var previousIndexByKid = new Dictionary<string, int>(previous.Keys.Count, StringComparer.Ordinal);
        for (var i = 0; i < previous.Keys.Count; i++)
            previousIndexByKid[previous.Keys[i].Kid] = i;

        for (var i = 0; i < newSet.Keys.Count; i++)
        {
            var kid = newSet.Keys[i].Kid;
            if (previousIndexByKid.TryGetValue(kid, out var previousIndex) &&
                ReferenceEquals(newSet.GetPrivateKey(i), previous.GetPrivateKey(previousIndex)))
            {
                return kid;
            }
        }

        return null;
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

    // ── KeySetOptions/KeySourceOptions implementation ───────────────────────────────────────────────

    /// <summary>
    /// Which options tier <c>TOptions</c>'s runtime instance derives from, decided once at
    /// construction. Drives which of the two independent state machines in this class
    /// (ADR 0011's <see cref="SigningKeySet"/>-based cache, or ADR 0015's snapshot-based one) is
    /// actually exercised by a given instance.
    /// </summary>
    private enum KeyRetrievalMode
    {
        /// <summary>ADR 0011 contract: <c>TOptions</c> derives from <see cref="StaticKeySourceOptions"/>
        /// or <see cref="RotatingKeySourceOptions"/>; <see cref="LoadKeysAsync"/> is authoritative.</summary>
        Legacy,

        /// <summary>ADR 0015 Tier A: <c>TOptions</c> derives from <see cref="KeySetOptions"/>.</summary>
        KeySet,

        /// <summary>ADR 0015 Tier B: <c>TOptions</c> derives from <see cref="KeySourceOptions"/>.</summary>
        KeySource,
    }

    private static KeyRetrievalMode ResolveRetrievalMode(TOptions options) => options switch
    {
        KeySourceOptions => KeyRetrievalMode.KeySource,
        KeySetOptions => KeyRetrievalMode.KeySet,
        _ => KeyRetrievalMode.Legacy,
    };

    /// <summary>
    /// Computes the state shared by both constructors — tier resolution, the time provider, and
    /// the ADR 0011 rotation-interval fields — without touching the ADR 0015
    /// retirement-window-provider/logger fields, which only the four-argument constructor sets.
    /// Returned rather than assigned directly, because C# forbids assigning a <see langword="readonly"/>
    /// field from anything other than a constructor body. Deliberately does not itself decide
    /// whether the resolved tier is legal for the calling constructor; each constructor makes that
    /// call so the two-argument overload can fail fast for a KeySetOptions/KeySourceOptions <c>TOptions</c> while the
    /// four-argument overload accepts it.
    /// </summary>
    private static (KeyRetrievalMode RetrievalMode, TimeProvider TimeProvider, TimeSpan? KeyRotationCheckInterval, TimeSpan? RefreshInterval)
        ResolveSharedState(IOptions<TOptions> options, TimeProvider timeProvider)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(timeProvider);

        TimeSpan? keyRotationCheckInterval = options.Value is RotatingKeySourceOptions rotating
            ? rotating.KeyRotationCheckInterval
            : null;

        TimeSpan? refreshInterval = options.Value is KeySourceOptions keySource
            ? keySource.RefreshInterval
            : null;

        return (ResolveRetrievalMode(options.Value), timeProvider, keyRotationCheckInterval, refreshInterval);
    }

    /// <summary>
    /// The immutable snapshot of public key data the ADR 0015 contract computes active-key
    /// selection and JWKS inclusion from. Rebuilt from scratch by <see cref="ListKeysAsync"/> —
    /// Tier A once, Tier B once per <see cref="KeySourceOptions.RefreshInterval"/> — and never
    /// mutated in place.
    /// </summary>
    private sealed class SigningKeySnapshot
    {
        public required IReadOnlyList<KeyListing> Listings { get; init; }

        public required IReadOnlyDictionary<string, KeyListing> ListingsById { get; init; }

        public required IReadOnlyDictionary<string, SigningKeyDescriptor> DescriptorsById { get; init; }

        public required IReadOnlyList<RotationEntry> Timeline { get; init; }
    }

    /// <summary>
    /// A refcounted wrapper over one <see cref="ISigner"/> activation, so an in-flight
    /// <see cref="ISigner.SignAsync"/> call can never race a handoff to a new active key: the
    /// signer is not disposed until every borrow has been returned (ADR 0011 §3.2's
    /// ordered-disposal rule, reused here per ADR 0015 §5 for both tiers).
    /// </summary>
    private sealed class SignerHandle
    {
        // Starts at 1, representing the base class's own persistent reference. Additional borrows
        // increment this before use and decrement after; the underlying ISigner is disposed once
        // the count reaches zero.
        private int _refCount = 1;

        // 0 = live, 1 = released. int so Interlocked.Exchange makes the transition atomic.
        private int _released;

        public required string Id { get; init; }

        public required SigningKeyDescriptor Descriptor { get; init; }

        public required ISigner Signer { get; init; }

        public bool TryBorrow()
        {
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

        public void Return()
        {
            if (Interlocked.Decrement(ref _refCount) == 0)
                Signer.Dispose();
        }

        /// <summary>
        /// Releases the base class's own persistent reference. The underlying <see cref="ISigner"/>
        /// is disposed only once every in-flight <see cref="TryBorrow"/> has also been returned.
        /// Safe to call multiple times.
        /// </summary>
        public void Release()
        {
            if (Interlocked.Exchange(ref _released, 1) != 0)
                return;

            Return();
        }
    }

    private async ValueTask<IReadOnlyList<SigningKeyDescriptor>> GetSigningKeysAsyncCore(
        CancellationToken cancellationToken)
    {
        var snapshot = await EnsureSnapshotAsync(cancellationToken).ConfigureAwait(false);
        var now = _timeProvider.GetUtcNow();

        var active = SigningKeyRotation.SelectActiveKey(snapshot.Timeline, now)
            ?? throw NoActiveKeyException();

        var retirementWindow = _retirementWindowProvider?.GetRetirementWindow() ?? TimeSpan.Zero;
        var included = SigningKeyRotation.SelectIncludedKeys(snapshot.Timeline, active, now, retirementWindow);

        return included.Select(entry => snapshot.DescriptorsById[entry.Key.Id]).ToList();
    }

    private async ValueTask<SigningResult> SignAsyncCore(
        ReadOnlyMemory<byte> payloadSegment, CancellationToken cancellationToken)
    {
        var snapshot = await EnsureSnapshotAsync(cancellationToken).ConfigureAwait(false);
        var handle = await EnsureActiveSignerAsync(snapshot, cancellationToken).ConfigureAwait(false);
        try
        {
            var headerBytes = BuildHeaderJsonBytes(handle.Descriptor.Algorithm, handle.Descriptor.Kid);
            var headerSegment = Base64UrlEncode(headerBytes);
            var signingInput = AssembleSigningInput(headerSegment, payloadSegment);

            var signatureBytes = await handle.Signer.SignAsync(signingInput, cancellationToken).ConfigureAwait(false);
            var signatureSegment = Base64UrlEncode(signatureBytes);

            return new SigningResult(headerSegment, signatureSegment, handle.Descriptor.Kid, handle.Descriptor.Algorithm);
        }
        finally
        {
            handle.Return();
        }
    }

    /// <summary>
    /// Returns the current immutable snapshot, building or refreshing it via
    /// <see cref="ListKeysAsync"/> when needed. Tier A builds it once and never rebuilds; Tier B
    /// rebuilds it once per <see cref="KeySourceOptions.RefreshInterval"/>.
    /// </summary>
    private async ValueTask<SigningKeySnapshot> EnsureSnapshotAsync(CancellationToken cancellationToken)
    {
        var now = _timeProvider.GetUtcNow();

        var current = Volatile.Read(ref _snapshot);
        if (current is not null && now < _snapshotExpiresAt)
            return current;

        await _snapshotLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            now = _timeProvider.GetUtcNow();
            if (_snapshot is not null && now < _snapshotExpiresAt)
                return _snapshot;

            var previous = _snapshot;
            var listings = await ListKeysAsync(cancellationToken).ConfigureAwait(false);
            var snapshot = BuildSnapshot(listings);

            if (previous is not null)
                EvaluateKillByOmission(previous, snapshot, now);

            LogStatusesAndWarnings(snapshot, now);

            _snapshot = snapshot;
            _snapshotExpiresAt = _retrievalMode == KeyRetrievalMode.KeySet
                ? DateTimeOffset.MaxValue // Tier A: ListKeysAsync is called exactly once, ever.
                : now.Add(_refreshInterval!.Value);

            return snapshot;
        }
        finally
        {
            _snapshotLock.Release();
        }
    }

    /// <summary>
    /// Recomputes active-key selection from <paramref name="snapshot"/> and <c>now</c>, and — only
    /// when the computed active <see cref="KeyId"/> has changed — calls <see cref="CreateSignerAsync"/>
    /// for the new active key and disposes (opportunistically, per ADR 0015 §5) the signer it
    /// supersedes. Returns a borrowed <see cref="SignerHandle"/> that the caller MUST
    /// <see cref="SignerHandle.Return"/> exactly once.
    /// </summary>
    private async ValueTask<SignerHandle> EnsureActiveSignerAsync(
        SigningKeySnapshot snapshot, CancellationToken cancellationToken)
    {
        var now = _timeProvider.GetUtcNow();
        var active = SigningKeyRotation.SelectActiveKey(snapshot.Timeline, now)
            ?? throw NoActiveKeyException();

        var current = Volatile.Read(ref _activeSignerHandle);
        if (current is not null && string.Equals(current.Id, active.Key.Id, StringComparison.Ordinal) && current.TryBorrow())
            return current;

        await _signerLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            // Re-check inside the lock: another caller may have already performed the handoff, or
            // the wall clock may have moved on again since the fast-path check above.
            now = _timeProvider.GetUtcNow();
            active = SigningKeyRotation.SelectActiveKey(snapshot.Timeline, now)
                ?? throw NoActiveKeyException();

            if (_activeSignerHandle is { } existing &&
                string.Equals(existing.Id, active.Key.Id, StringComparison.Ordinal))
            {
                existing.TryBorrow();
                return existing;
            }

            var activeId = new KeyId(active.Key.Id);
            var signer = await CreateSignerAsync(activeId, cancellationToken).ConfigureAwait(false);
            var descriptor = snapshot.DescriptorsById[active.Key.Id];

            if (signer.Algorithm != descriptor.Algorithm)
            {
                signer.Dispose();

                throw new ZeeKayDaConfigurationException(
                    new ZeeKayDaConfigurationFailure(
                        "signing.signer_algorithm_mismatch",
                        $"The signer returned by {nameof(CreateSignerAsync)} for key '{activeId.Value}' " +
                        $"signs under {signer.Algorithm}, but the key was listed with algorithm " +
                        $"{descriptor.Algorithm}. The signer's {nameof(ISigner.Algorithm)} must match " +
                        $"the key's declared algorithm exactly."));
            }

            var newHandle = new SignerHandle { Id = activeId.Value, Descriptor = descriptor, Signer = signer };
            var previous = _activeSignerHandle;
            _activeSignerHandle = newHandle;

            // Releases the base class's own reference on the superseded signer. Per ADR 0015 §5,
            // the underlying private material is reclaimed once every in-flight SignAsync borrow on
            // it has also returned — immediately for Tier A's typical idle handoff, or after the
            // last in-flight signing call completes for a concurrently-borrowed Tier B signer.
            previous?.Release();

            newHandle.TryBorrow();
            return newHandle;
        }
        finally
        {
            _signerLock.Release();
        }
    }

    /// <summary>
    /// Builds a validated immutable snapshot from a freshly returned <see cref="ListKeysAsync"/>
    /// result: derives each listing's <c>kid</c>, rejects duplicates, and runs
    /// algorithm-compatibility/key-strength validation over every listing — all before any
    /// <see cref="CreateSignerAsync"/> call (ADR 0015 §2/§7).
    /// </summary>
    private static SigningKeySnapshot BuildSnapshot(IReadOnlyList<KeyListing> listings)
    {
        ArgumentNullException.ThrowIfNull(listings);

        var seenKids = new HashSet<string>(StringComparer.Ordinal);
        var descriptorsById = new Dictionary<string, SigningKeyDescriptor>(listings.Count, StringComparer.Ordinal);
        var listingsById = new Dictionary<string, KeyListing>(listings.Count, StringComparer.Ordinal);
        var rotationKeys = new RotationKey[listings.Count];

        for (var i = 0; i < listings.Count; i++)
        {
            var listing = listings[i];
            var descriptor = BuildDescriptorFromListing(listing);

            if (!seenKids.Add(descriptor.Kid))
            {
                throw new ZeeKayDaConfigurationException(
                    new ZeeKayDaConfigurationFailure(
                        "signing.duplicate_kid",
                        $"The signing key listing contains duplicate kid '{descriptor.Kid}'. " +
                        "Each key must have a unique, stable identifier."));
            }

            ValidateListing(listing, descriptor);

            descriptorsById[listing.Id.Value] = descriptor;
            listingsById[listing.Id.Value] = listing;
            rotationKeys[i] = new RotationKey(listing.Id.Value, listing.ActivateAt ?? DateTimeOffset.MinValue, listing.ExpiresAt);
        }

        return new SigningKeySnapshot
        {
            Listings = listings,
            ListingsById = listingsById,
            DescriptorsById = descriptorsById,
            Timeline = SigningKeyRotation.BuildActivationTimeline(rotationKeys),
        };
    }

    /// <summary>
    /// Derives a <see cref="SigningKeyDescriptor"/> — and therefore its <c>kid</c> — from a
    /// <see cref="KeyListing"/>'s public key material, never from <see cref="KeyListing.Id"/>.
    /// </summary>
    private static SigningKeyDescriptor BuildDescriptorFromListing(KeyListing listing)
    {
        return listing.PublicKey.KeyType switch
        {
            SigningKeyType.Rsa => BuildRsaDescriptor(listing),
            SigningKeyType.Ec => BuildEcDescriptor(listing),
            _ => throw new NotSupportedException($"Signing key type {listing.PublicKey.KeyType} is not supported."),
        };

        static SigningKeyDescriptor BuildRsaDescriptor(KeyListing listing)
        {
            var rsaParams = listing.PublicKey.RsaPublicParameters!.Value;
            var kid = JwkThumbprint.Compute(rsaParams);
            return new SigningKeyDescriptor(kid, listing.Algorithm, rsaParams);
        }

        static SigningKeyDescriptor BuildEcDescriptor(KeyListing listing)
        {
            var ecParams = listing.PublicKey.EcPublicParameters!.Value;
            var kid = JwkThumbprint.Compute(ecParams);
            return new SigningKeyDescriptor(kid, listing.Algorithm, ecParams);
        }
    }

    /// <summary>
    /// Runs the same algorithm-compatibility and key-strength checks the ADR 0011 contract runs at
    /// load time, over public data only: a public-only <see cref="RSA"/>/<see cref="ECDsa"/> object
    /// is imported purely so <see cref="SigningAlgorithms.ValidateKeyAlgorithmCompatibility"/> can
    /// inspect its runtime type and curve — no private material is ever involved.
    /// </summary>
    private static void ValidateListing(KeyListing listing, SigningKeyDescriptor descriptor)
    {
        if (listing.PublicKey.KeyType == SigningKeyType.Rsa)
        {
            using var rsa = RSA.Create();
            rsa.ImportParameters(listing.PublicKey.RsaPublicParameters!.Value);
            SigningAlgorithms.ValidateKeyAlgorithmCompatibility(descriptor, rsa);
        }
        else
        {
            using var ec = ECDsa.Create();
            ec.ImportParameters(listing.PublicKey.EcPublicParameters!.Value);
            SigningAlgorithms.ValidateKeyAlgorithmCompatibility(descriptor, ec);
        }

        SigningAlgorithms.ValidateKeyStrength(descriptor);
    }

    /// <summary>
    /// Implements ADR 0015 §6's three-state kill-by-omission disambiguation for every key present
    /// in <paramref name="previous"/> but missing from <paramref name="current"/>: silent when the
    /// vanished key's derived retirement window (computed from <paramref name="previous"/>'s own
    /// timeline) had already closed, or a <see cref="Microsoft.Extensions.Logging.LogLevel.Warning"/>
    /// when it vanished while still inside that window. A failed or partial read is not this
    /// method's concern — that is <see cref="ListKeysAsync"/>'s completeness contract, enforced by
    /// simply never catching what it throws.
    /// </summary>
    private void EvaluateKillByOmission(SigningKeySnapshot previous, SigningKeySnapshot current, DateTimeOffset now)
    {
        var retirementWindow = _retirementWindowProvider?.GetRetirementWindow() ?? TimeSpan.Zero;

        foreach (var id in previous.Listings
                     .Select(previousListing => previousListing.Id.Value)
                     .Where(id => !current.ListingsById.ContainsKey(id)))
        {
            var withinRetirementWindow = true;
            foreach (var entry in previous.Timeline.Where(entry =>
                         string.Equals(entry.Key.Id, id, StringComparison.Ordinal)))
            {
                // RetiredAt is null when the key had not (yet) been legitimately superseded as of
                // the previous snapshot — vanishing before that point is unambiguously premature.
                // Otherwise, "post-window" means the derived retirement window has already elapsed.
                withinRetirementWindow = entry.RetiredAt is null || now - entry.RetiredAt.Value <= retirementWindow;
                break;
            }

            if (withinRetirementWindow)
            {
                _logger?.LogWarning(
                    "ZeeKayDa.Auth: signing key '{KeyId}' stopped appearing in {ServiceType}.ListKeysAsync " +
                    "while still inside its retirement window. It has been dropped from the JWKS on this " +
                    "refresh regardless (the kill switch still fires), but an early vanish while still " +
                    "trusted usually means an accidental key deletion rather than normal end-of-life " +
                    "rotation (ADR 0015 §6).",
                    id, GetType().Name);
            }
        }
    }

    /// <summary>
    /// Logs a per-key status line for every key in <paramref name="snapshot"/>, and — for a Tier A
    /// (<see cref="KeySetOptions"/>) provider only — the too-soon-pending-activation warning derived
    /// from <see cref="KeySetOptions.PublicationLead"/>.
    /// </summary>
    private void LogStatusesAndWarnings(SigningKeySnapshot snapshot, DateTimeOffset now)
    {
        if (_options.Value is not KeySetOptions keySetOptions)
            return;

        var active = SigningKeyRotation.SelectActiveKey(snapshot.Timeline, now);
        if (active is null)
        {
            // No key is currently eligible to sign. The base class fails closed with its own
            // ZeeKayDaConfigurationException on the very next GetSigningKeysAsync/SignAsync call —
            // nothing further to log here.
            return;
        }

        var retirementWindow = _retirementWindowProvider?.GetRetirementWindow() ?? TimeSpan.Zero;
        var included = SigningKeyRotation.SelectIncludedKeys(snapshot.Timeline, active.Value, now, retirementWindow);
        var includedIds = new HashSet<string>(included.Select(entry => entry.Key.Id), StringComparer.Ordinal);

        foreach (var entry in snapshot.Timeline)
        {
            var status = DescribeKeyStatus(entry, active.Value, includedIds, now, retirementWindow);
            var metadata = DescribeKeyMetadata(entry.Key.Id);
            var details = metadata is null ? $"expires {entry.Key.ExpiresAt:O}" : $"{metadata}, expires {entry.Key.ExpiresAt:O}";

            _logger?.LogInformation(
                "ZeeKayDa.Auth: signing key '{KeyId}' ({Details}) is {Status}.",
                entry.Key.Id, details, status);
        }

        if (SigningKeyRotation.HasTooSoonPendingActivation(snapshot.Timeline, active.Value, now, keySetOptions.PublicationLead, out var soonestPending))
        {
            _logger?.LogWarning(
                "ZeeKayDa.Auth: signing key '{KeyId}' activates at {ActivatesAt:O}, which is less than " +
                "PublicationLead ({PublicationLead}) away from now. A relying party polling the JWKS may " +
                "not have observed this key's public material before it starts signing.",
                soonestPending!.Value.Key.Id, soonestPending.Value.ActivatesAt, keySetOptions.PublicationLead);
        }

        if (active.Value.Key.ExpiresAt - now <= TimeSpan.FromDays(30))
        {
            _logger?.LogWarning(
                "ZeeKayDa.Auth: the active signing key '{KeyId}' expires at {ExpiresAt:O}, within 30 " +
                "days. Rotate in a new key before it expires.",
                active.Value.Key.Id, active.Value.Key.ExpiresAt);
        }
    }

    private static string DescribeKeyStatus(
        RotationEntry entry, RotationEntry active, HashSet<string> includedIds, DateTimeOffset now, TimeSpan retirementWindow)
    {
        if (string.Equals(entry.Key.Id, active.Key.Id, StringComparison.Ordinal))
            return "the active signer";

        if (!includedIds.Contains(entry.Key.Id))
        {
            return "NOT included in the JWKS - its retirement window has fully elapsed; safe to remove " +
                "from configuration";
        }

        if (entry.ActivatesAt > now)
            return $"included in the JWKS, not yet active (activates at {entry.ActivatesAt:O})";

        return "included in the JWKS, retired but still within its retirement window (until " +
            $"{entry.RetiredAt!.Value + retirementWindow:O})";
    }

    /// <summary>
    /// Supplies extra per-key display metadata for the informational status line
    /// <see cref="LogStatusesAndWarnings"/> logs (for example, key type and size). Returns
    /// <see langword="null"/> by default.
    /// </summary>
    /// <param name="id">The provider's own identifier for the key, as it appeared on a
    /// <see cref="KeyListing"/> returned by <see cref="ListKeysAsync"/>.</param>
    protected virtual string? DescribeKeyMetadata(string id) => null;

    private static ZeeKayDaConfigurationException NoActiveKeyException() =>
        new(new ZeeKayDaConfigurationFailure(
            "signing.no_active_key",
            "No signing key is currently eligible to be the active signer — every configured key " +
            "has either not yet activated or has already expired. Refusing to sign rather than " +
            "picking an ineligible key (ADR 0015 §3/Security Considerations item 3)."));
}
