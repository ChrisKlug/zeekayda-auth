using System.Buffers;
using System.Buffers.Text;
using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using ZeeKayDa.Auth.Logging;

namespace ZeeKayDa.Auth.Tokens;

/// <summary>
/// Abstract base class for <see cref="IJwtSigningService"/> implementations. Provides immutable-
/// snapshot key-listing caching (once for a <see cref="KeySetOptions"/> provider, or on a
/// recurring cadence for a <see cref="KeySourceOptions"/> provider), lazy active-key
/// selection, key-algorithm compatibility validation, deterministic disposal of superseded signers,
/// and the JWS signing operation. Implementors provide only <see cref="ListKeysAsync"/> and
/// <see cref="CreateSignerAsync"/>.
/// </summary>
/// <typeparam name="TOptions">
/// The provider-specific options type. Must derive from <see cref="KeySetOptions"/> (a fixed
/// key set known at configuration time) or <see cref="KeySourceOptions"/> (a source the base
/// class re-reads on a cadence).
/// </typeparam>
public abstract class JwtSigningService<TOptions> : IJwtSigningService, ISigningStartupSelfTest, IAsyncDisposable
    where TOptions : JwtSigningServiceOptions
{
    // Never a valid JWS (no '.' separator, contains a space), so it can't be mistaken for one even
    // if a self-test signature were somehow leaked.
    private static readonly ReadOnlyMemory<byte> SelfTestPayload = "zeekayda-auth signing self-test"u8.ToArray();

    private readonly TimeProvider _timeProvider;
    private readonly bool _isKeySet; // true = KeySetOptions; false = KeySourceOptions.
    private readonly IOptions<TOptions> _options;
    private readonly TimeSpan? _refreshInterval; // KeySourceOptions only.
    private readonly ISigningKeyRetirementWindowProvider _retirementWindowProvider;
    private readonly ISanitizingLogger<JwtSigningService<TOptions>> _logger;

    private readonly SemaphoreSlim _snapshotLock = new(1, 1);
    private readonly SemaphoreSlim _signerLock = new(1, 1);
    private SigningKeySnapshot? _snapshot;
    private SignerHandle? _activeSignerHandle;

    // 0 = live, 1 = disposed. int so Interlocked.Exchange makes the transition atomic.
    private int _disposeState;

    /// <summary>
    /// Initialises the base class.
    /// </summary>
    /// <param name="options">The provider-specific options.</param>
    /// <param name="timeProvider">
    /// The time provider used for snapshot-expiry and activation-timeline calculations. Inject
    /// <see cref="TimeProvider"/> from DI or use <c>TimeProvider.System</c> in production and a
    /// <c>FakeTimeProvider</c> in tests.
    /// </param>
    /// <param name="retirementWindowProvider">
    /// Supplies the derived retirement window used to compute which keys are
    /// currently included in the JWKS, and to disambiguate a kill-by-omission vanish as
    /// within-window versus post-window.
    /// </param>
    /// <param name="logger">
    /// Used to emit a <see cref="Microsoft.Extensions.Logging.LogLevel.Warning"/> when a
    /// <see cref="KeySourceOptions"/> provider's key listing drops a key while it is still inside
    /// its retirement window.
    /// </param>
    protected JwtSigningService(
        IOptions<TOptions> options,
        TimeProvider timeProvider,
        ISigningKeyRetirementWindowProvider retirementWindowProvider,
        ISanitizingLogger<JwtSigningService<TOptions>> logger)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(timeProvider);
        ArgumentNullException.ThrowIfNull(retirementWindowProvider);
        ArgumentNullException.ThrowIfNull(logger);

        _timeProvider = timeProvider;
        _options = options;
        _retirementWindowProvider = retirementWindowProvider;
        _logger = logger;

        _isKeySet = options.Value is KeySetOptions;
        _refreshInterval = options.Value is KeySourceOptions keySource ? keySource.RefreshInterval : null;
    }

    /// <summary>
    /// Returns the current listing of trusted signing keys as pure public metadata — never private
    /// material. A <see cref="KeySetOptions"/> provider: called exactly once, ever. A
    /// <see cref="KeySourceOptions"/> provider: called once per <see cref="KeySourceOptions.RefreshInterval"/>.
    /// </summary>
    /// <param name="cancellationToken">A token to cancel the operation.</param>
    /// <returns>Every currently trusted key's public listing. Must never be empty.</returns>
    /// <remarks>
    /// Carries a <b>completeness contract</b>: a provider that cannot produce a complete read of
    /// its current key set <b>MUST throw</b> rather than return a short or partial list. A vanished
    /// key is trusted to mean "no longer trusted" (kill-by-omission); a failed read must never be
    /// indistinguishable from that. The base class never catches or downgrades an exception from
    /// this method — it always propagates straight to the caller, fail-closed.
    /// </remarks>
    protected abstract ValueTask<IReadOnlyList<KeyListing>> ListKeysAsync(CancellationToken cancellationToken);

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
    /// A local provider returns a <see cref="LocalSigner"/>; a remote provider (Key Vault, a KMS, an
    /// HSM) returns its own <see cref="ISigner"/> whose <see cref="ISigner.SignAsync"/> makes a
    /// network call — the private key never becomes local.
    /// </remarks>
    protected abstract ValueTask<ISigner> CreateSignerAsync(KeyId id, CancellationToken cancellationToken);

    /// <inheritdoc/>
    public async ValueTask<IReadOnlyList<SigningKeyDescriptor>> GetSigningKeysAsync(
        CancellationToken cancellationToken = default)
    {
        var snapshot = await EnsureSnapshotAsync(cancellationToken).ConfigureAwait(false);
        var now = _timeProvider.GetUtcNow();

        var active = SigningKeyRotation.SelectActiveKey(snapshot.Timeline, now, SupportsBootstrapExemption)
            ?? throw NoActiveKeyException();

        var retirementWindow = _retirementWindowProvider.GetRetirementWindow();
        var included = SigningKeyRotation.SelectIncludedKeys(snapshot.Timeline, active, now, retirementWindow);

        return included.Select(entry => snapshot.DescriptorsById[entry.Key.Id]).ToList();
    }

    /// <inheritdoc/>
    public async ValueTask<SigningResult> SignAsync(
        ReadOnlyMemory<byte> payloadSegment,
        CancellationToken cancellationToken = default)
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
    /// Forces materialization of the currently active signer exactly as <see cref="SignAsync"/>
    /// would, so <c>SigningStartupSelfTestHostedService</c> can surface a signing failure at host
    /// startup rather than on the first real token-issuing request.
    /// </summary>
    /// <remarks>
    /// Explicit-interface-implemented rather than <see langword="virtual"/> so no derived provider
    /// can override or weaken the self-test.
    /// </remarks>
    async ValueTask ISigningStartupSelfTest.VerifyActiveSignerAsync(CancellationToken cancellationToken)
    {
        var snapshot = await EnsureSnapshotAsync(cancellationToken).ConfigureAwait(false);
        var handle = await EnsureActiveSignerAsync(snapshot, cancellationToken).ConfigureAwait(false);
        handle.Return();
    }

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
    /// There is no <c>base.OnDisposeAsync()</c> call to remember — the base class's own cleanup
    /// always runs regardless of what this override does. Called at most once, guarded by
    /// <see cref="DisposeAsync"/>'s own idempotency check.
    /// </remarks>
    protected virtual ValueTask OnDisposeAsync() => ValueTask.CompletedTask;

    /// <summary>
    /// Supplies extra per-key display metadata for the informational status line
    /// <see cref="LogStatusesAndWarnings"/> logs (for example, key type and size). Returns
    /// <see langword="null"/> by default.
    /// </summary>
    /// <param name="id">The provider's own identifier for the key, as it appeared on a
    /// <see cref="KeyListing"/> returned by <see cref="ListKeysAsync"/>.</param>
    protected virtual string? DescribeKeyMetadata(string id) => null;

    /// <summary>
    /// Releases the base class's own resources: the active-signer handle and the internal locks.
    /// </summary>
    private async ValueTask DisposeBaseResourcesAsync()
    {
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
    /// Writes the JWS header <c>{"alg":"&lt;algorithm&gt;","kid":"&lt;kid&gt;","typ":"JWT"}</c>
    /// as UTF-8 bytes using <see cref="Utf8JsonWriter"/> — no intermediate string allocation.
    /// </summary>
    /// <remarks>
    /// <see cref="SigningAlgorithm"/> member names match the RFC 7518 string identifiers exactly, so
    /// <c>algorithm.ToString()</c> produces the correct <c>alg</c> value directly.
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

    // ── KeySetOptions/KeySourceOptions state ────────────────────────────────────────────────────────

    /// <summary>
    /// <see langword="true"/> only for a <see cref="KeySetOptions"/> provider — passed as
    /// <c>supportsBootstrapExemption</c> to every <see cref="SigningKeyRotation.SelectActiveKey"/>
    /// call. Gated on the provider's options type rather than snapshot/process lifetime, so a
    /// <see cref="KeySourceOptions"/> listing that has shrunk to one key via revocation cannot
    /// re-arm the exemption on process restart.
    /// </summary>
    private bool SupportsBootstrapExemption => _isKeySet;

    /// <summary>
    /// The immutable snapshot of public key data active-key selection and JWKS inclusion are
    /// computed from. Rebuilt from scratch by <see cref="ListKeysAsync"/> — once for a
    /// <see cref="KeySetOptions"/> provider, or once per <see cref="KeySourceOptions.RefreshInterval"/>
    /// for a <see cref="KeySourceOptions"/> provider — and never mutated in place.
    /// </summary>
    /// <remarks>
    /// <c>ExpiresAt</c> lives on this record rather than a separate field so
    /// <see cref="EnsureSnapshotAsync"/>'s lock-free fast path can read the snapshot reference and
    /// its expiry atomically via a single <see cref="System.Threading.Volatile"/> read.
    /// </remarks>
    private sealed class SigningKeySnapshot
    {
        public required IReadOnlyList<KeyListing> Listings { get; init; }

        public required IReadOnlyDictionary<string, KeyListing> ListingsById { get; init; }

        public required IReadOnlyDictionary<string, SigningKeyDescriptor> DescriptorsById { get; init; }

        public required IReadOnlyList<RotationEntry> Timeline { get; init; }

        public required DateTimeOffset ExpiresAt { get; init; }
    }

    /// <summary>
    /// A refcounted wrapper over one <see cref="ISigner"/> activation, so an in-flight
    /// <see cref="ISigner.SignAsync"/> call can never race a handoff to a new active key: the
    /// signer is not disposed until every borrow has been returned.
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

    /// <summary>
    /// Returns the current immutable snapshot, building or refreshing it via
    /// <see cref="ListKeysAsync"/> when needed. A <see cref="KeySetOptions"/> provider builds it
    /// once and never rebuilds; a <see cref="KeySourceOptions"/> provider rebuilds it once per
    /// <see cref="KeySourceOptions.RefreshInterval"/>.
    /// </summary>
    private async ValueTask<SigningKeySnapshot> EnsureSnapshotAsync(CancellationToken cancellationToken)
    {
        var now = _timeProvider.GetUtcNow();

        var current = Volatile.Read(ref _snapshot);
        if (current is not null && now < current.ExpiresAt)
            return current;

        await _snapshotLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            now = _timeProvider.GetUtcNow();
            if (_snapshot is not null && now < _snapshot.ExpiresAt)
                return _snapshot;

            var previous = _snapshot;
            IReadOnlyList<KeyListing> listings;
            try
            {
                listings = await ListKeysAsync(cancellationToken).ConfigureAwait(false);
            }
            catch (Exception ex) when (ex is not OperationCanceledException || !cancellationToken.IsCancellationRequested)
            {
                // A ListKeysAsync failure here (including a revocation that leaves zero enabled
                // keys) must not leave a previously cached active signer's private key resident
                // indefinitely, so it is released unconditionally rather than trying to distinguish
                // a genuine revocation from a transient failure at this layer.
                //
                // The filter excludes the caller's own cancellationToken firing: releasing on that
                // would let a client repeatedly cancel requests to force a healthy signer's private
                // key to be re-downloaded from a remote provider on every call — an amplification
                // vector that needs no actual key compromise, only the ability to drop a request.
                await ReleaseActiveSignerAsync().ConfigureAwait(false);
                throw;
            }

            var expiresAt = _isKeySet
                ? DateTimeOffset.MaxValue // KeySetOptions: ListKeysAsync is called exactly once, ever.
                : now.Add(_refreshInterval!.Value);
            var snapshot = BuildSnapshot(listings, expiresAt);

            if (previous is not null)
                EvaluateKillByOmission(previous, snapshot, now);

            LogStatusesAndWarnings(snapshot, now);

            _snapshot = snapshot;

            return snapshot;
        }
        finally
        {
            _snapshotLock.Release();
        }
    }

    /// <summary>
    /// Releases the currently cached active signer, if any, so its private key material is not
    /// left resident in process memory.
    /// </summary>
    private async ValueTask ReleaseActiveSignerAsync()
    {
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
    }

    /// <summary>
    /// Recomputes active-key selection from <paramref name="snapshot"/> and <c>now</c>, and — only
    /// when the active <see cref="KeyId"/> has changed — calls <see cref="CreateSignerAsync"/> for
    /// the new active key, self-tests it (signs <see cref="SelfTestPayload"/> and verifies against
    /// the key's own listed public key via <see cref="SigningAlgorithms.Verify"/>), and disposes the
    /// signer it supersedes. Returns a borrowed <see cref="SignerHandle"/> that the caller MUST
    /// <see cref="SignerHandle.Return"/> exactly once.
    /// </summary>
    private async ValueTask<SignerHandle> EnsureActiveSignerAsync(
        SigningKeySnapshot snapshot, CancellationToken cancellationToken)
    {
        var now = _timeProvider.GetUtcNow();
        var active = SigningKeyRotation.SelectActiveKey(snapshot.Timeline, now, SupportsBootstrapExemption)
            ?? throw NoActiveKeyException();
        var activeDescriptor = snapshot.DescriptorsById[active.Key.Id];

        var current = Volatile.Read(ref _activeSignerHandle);
        if (current is not null &&
            string.Equals(current.Id, active.Key.Id, StringComparison.Ordinal) &&
            string.Equals(current.Descriptor.Kid, activeDescriptor.Kid, StringComparison.Ordinal) &&
            current.TryBorrow())
        {
            return current;
        }

        await _signerLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            // Re-check inside the lock: another caller may have already performed the handoff, or
            // the wall clock may have moved on again since the fast-path check above.
            now = _timeProvider.GetUtcNow();
            active = SigningKeyRotation.SelectActiveKey(snapshot.Timeline, now, SupportsBootstrapExemption)
                ?? throw NoActiveKeyException();
            activeDescriptor = snapshot.DescriptorsById[active.Key.Id];

            if (_activeSignerHandle is { } existing &&
                string.Equals(existing.Id, active.Key.Id, StringComparison.Ordinal) &&
                string.Equals(existing.Descriptor.Kid, activeDescriptor.Kid, StringComparison.Ordinal) &&
                existing.TryBorrow())
            {
                return existing;
            }

            var activeId = new KeyId(active.Key.Id);
            var signer = await CreateSignerAsync(activeId, cancellationToken).ConfigureAwait(false);
            var descriptor = activeDescriptor;

            if (_activeSignerHandle is { } stale && ReferenceEquals(signer, stale.Signer))
            {
                // Do not dispose `signer` here — it is the same instance as the currently installed
                // handle's own signer, and that handle is still live and in use.
                throw new ZeeKayDaConfigurationException(
                    new ZeeKayDaConfigurationFailure(
                        "signing.signer_reused",
                        $"{GetType().Name}.{nameof(CreateSignerAsync)} returned the same {nameof(ISigner)} " +
                        "instance as the currently active signer. Every call must return a freshly " +
                        $"created, exclusively owned signer — see {nameof(ISigner)}'s Dispose contract."));
            }

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

            // Proves the signer's private key actually pairs with the public key it publishes a kid
            // for, before it is ever used to produce a real token. Runs on every handoff, not only
            // at process start.
            bool selfTestVerified;
            try
            {
                var selfTestSignature = await signer.SignAsync(SelfTestPayload, cancellationToken).ConfigureAwait(false);
                selfTestVerified = SigningAlgorithms.Verify(descriptor, SelfTestPayload.Span, selfTestSignature.Span);
            }
            catch
            {
                // A missing Key Vault "sign" permission or an inaccessible CNG key container
                // surfaces as an exception here, not as a verification mismatch below — the signer
                // must still be disposed rather than leaked before the failure propagates.
                signer.Dispose();
                throw;
            }

            if (!selfTestVerified)
            {
                signer.Dispose();

                throw new ZeeKayDaConfigurationException(
                    new ZeeKayDaConfigurationFailure(
                        "signing.self_test_failed",
                        $"The signer {nameof(CreateSignerAsync)} returned for key '{descriptor.Kid}' " +
                        "produced a signature that does not verify against that key's own listed public " +
                        "key. The private key materialized for signing does not match the public key " +
                        $"published under this kid — refusing to serve tokens under '{descriptor.Kid}'."));
            }

            var newHandle = new SignerHandle { Id = activeId.Value, Descriptor = descriptor, Signer = signer };
            var previous = _activeSignerHandle;
            _activeSignerHandle = newHandle;

            // Releases the base class's own reference; the superseded signer's private material is
            // reclaimed once every in-flight SignAsync borrow on it has also returned.
            previous?.Release();

            // Cannot fail: newHandle was just constructed at refcount 1, not yet published, and we
            // are still holding _signerLock.
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
    /// result: derives each listing's <c>kid</c>, rejects duplicate <c>kid</c>s and duplicate
    /// <see cref="KeyId.Value"/>s, and runs algorithm-compatibility/key-strength validation over
    /// every listing — all before any <see cref="CreateSignerAsync"/> call.
    /// </summary>
    private static SigningKeySnapshot BuildSnapshot(IReadOnlyList<KeyListing> listings, DateTimeOffset expiresAt)
    {
        ArgumentNullException.ThrowIfNull(listings);

        var seenKids = new HashSet<string>(StringComparer.Ordinal);
        var seenIds = new HashSet<string>(StringComparer.Ordinal);
        var descriptorsById = new Dictionary<string, SigningKeyDescriptor>(listings.Count, StringComparer.Ordinal);
        var listingsById = new Dictionary<string, KeyListing>(listings.Count, StringComparer.Ordinal);
        var rotationKeys = new RotationKey[listings.Count];

        for (var i = 0; i < listings.Count; i++)
        {
            var listing = listings[i];

            if (!seenIds.Add(listing.Id.Value))
            {
                throw new ZeeKayDaConfigurationException(
                    new ZeeKayDaConfigurationFailure(
                        "signing.duplicate_key_id",
                        $"The signing key listing contains duplicate provider key id '{listing.Id.Value}'. " +
                        "Each KeyListing.Id must be unique among every listing returned by ListKeysAsync."));
            }

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
            Listings = listings.ToArray(),
            ListingsById = listingsById,
            DescriptorsById = descriptorsById,
            Timeline = SigningKeyRotation.BuildActivationTimeline(rotationKeys),
            ExpiresAt = expiresAt,
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
    /// Runs the same algorithm-compatibility and key-strength checks the base class always runs at
    /// snapshot-build time, over public data only: a public-only <see cref="RSA"/>/<see cref="ECDsa"/>
    /// object is imported purely so <see cref="SigningAlgorithms.ValidateKeyAlgorithmCompatibility"/>
    /// can inspect its runtime type and curve — no private material is ever involved.
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
    /// Logs a <see cref="Microsoft.Extensions.Logging.LogLevel.Warning"/> for every key present in
    /// <paramref name="previous"/> but missing from <paramref name="current"/> while its derived
    /// retirement window was still open — silent once that window has closed.
    /// </summary>
    private void EvaluateKillByOmission(SigningKeySnapshot previous, SigningKeySnapshot current, DateTimeOffset now)
    {
        var retirementWindow = _retirementWindowProvider.GetRetirementWindow();

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
                _logger.LogWarning(
                    "ZeeKayDa.Auth: signing key '{KeyId}' stopped appearing in {ServiceType}.ListKeysAsync " +
                    "while still inside its retirement window. It has been dropped from the JWKS on this " +
                    "refresh regardless (the kill switch still fires), but an early vanish while still " +
                    "trusted usually means an accidental key deletion rather than normal end-of-life " +
                    "rotation.",
                    id, GetType().Name);
            }
        }
    }

    /// <summary>
    /// Logs a per-key status line for every key in <paramref name="snapshot"/>, and — for a
    /// <see cref="KeySetOptions"/> provider only — the too-soon-pending-activation warning derived
    /// from <see cref="KeySetOptions.PublicationLead"/>.
    /// </summary>
    private void LogStatusesAndWarnings(SigningKeySnapshot snapshot, DateTimeOffset now)
    {
        if (_options.Value is not KeySetOptions keySetOptions)
            return;

        var active = SigningKeyRotation.SelectActiveKey(snapshot.Timeline, now, SupportsBootstrapExemption);
        if (active is null)
        {
            // No key is currently eligible to sign. The base class fails closed with its own
            // ZeeKayDaConfigurationException on the very next GetSigningKeysAsync/SignAsync call —
            // nothing further to log here.
            return;
        }

        var retirementWindow = _retirementWindowProvider.GetRetirementWindow();
        var included = SigningKeyRotation.SelectIncludedKeys(snapshot.Timeline, active.Value, now, retirementWindow);
        var includedIds = new HashSet<string>(included.Select(entry => entry.Key.Id), StringComparer.Ordinal);

        foreach (var entry in snapshot.Timeline)
        {
            var status = DescribeKeyStatus(entry, active.Value, includedIds, now, retirementWindow);
            var metadata = DescribeKeyMetadata(entry.Key.Id);
            var details = metadata is null ? $"expires {entry.Key.ExpiresAt:O}" : $"{metadata}, expires {entry.Key.ExpiresAt:O}";

            _logger.LogInformation(
                "ZeeKayDa.Auth: signing key '{KeyId}' ({Details}) is {Status}.",
                entry.Key.Id, details, status);
        }

        if (SigningKeyRotation.HasTooSoonPendingActivation(snapshot.Timeline, active.Value, now, keySetOptions.PublicationLead, out var soonestPending))
        {
            _logger.LogWarning(
                "ZeeKayDa.Auth: signing key '{KeyId}' activates at {ActivatesAt:O}, which is less than " +
                "PublicationLead ({PublicationLead}) away from now. A relying party polling the JWKS may " +
                "not have observed this key's public material before it starts signing.",
                soonestPending!.Value.Key.Id, soonestPending.Value.ActivatesAt, keySetOptions.PublicationLead);
        }

        if (active.Value.Key.ExpiresAt - now <= TimeSpan.FromDays(30))
        {
            _logger.LogWarning(
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

    private static ZeeKayDaConfigurationException NoActiveKeyException() =>
        new(new ZeeKayDaConfigurationFailure(
            "signing.no_active_key",
            "No signing key is currently eligible to be the active signer — every configured key " +
            "has either not yet activated or has already expired. Refusing to sign rather than " +
            "picking an ineligible key."));
}
