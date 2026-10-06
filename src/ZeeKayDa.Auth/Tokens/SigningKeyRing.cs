namespace ZeeKayDa.Auth.Tokens;

/// <summary>
/// What every signing consumer depends on: the current <see cref="SigningKeySet"/>, and the ability
/// to sign with the key currently designated as the signer. Reads its <see cref="ISigningKeySource"/>
/// exactly once at startup, builds the key set, opens and self-tests the signer, then never reads
/// again.
/// </summary>
/// <remarks>
/// <para>
/// <strong>Framework-owned.</strong> The constructor is <see langword="internal"/>: nothing outside
/// the framework can construct or substitute a ring, so no consumer can be handed a key set that
/// skipped the startup self-test. A third party extends signing by implementing
/// <see cref="ISigningKeySource"/> instead.
/// </para>
/// <para>
/// <see cref="SignAsync{TState}"/>'s callback is synchronous by design: the caller cannot perform
/// I/O while the key is resolved, and the returned <see cref="SigningOutcome"/> makes header/key
/// disagreement unrepresentable rather than merely detected.
/// </para>
/// <para>
/// Owns the one <see cref="ISigner"/> it opens for the process lifetime and disposes it once, at
/// shutdown — a consumer never receives it and never disposes it. Also owns the
/// <see cref="ISigningKeySource"/> it was constructed over: nothing else in the container holds a
/// reference to it, so the ring disposes it once, at shutdown, normally after the signer — via
/// <see cref="IDisposable.Dispose"/> or <see cref="IAsyncDisposable.DisposeAsync"/>, whichever the
/// host calls. The one exception is disposal racing <see cref="EnsureInitializedAsync"/> before the
/// signer has committed, in which case the source is disposed first.
/// </para>
/// </remarks>
public sealed class SigningKeyRing : IDisposable, IAsyncDisposable
{
    private readonly ISigningKeySource _source;
    private readonly TimeProvider _timeProvider;

    // The signing key set and the signer opened for it, written together exactly once by the one
    // initialization — never as two independently-updated fields — so a consumer can never observe
    // one without the other.
    private SignerBinding? _binding;

    // 0 = live, 1 = disposed. int so Interlocked.Exchange makes the transition atomic.
    private int _disposed;

    // 0 = the committed signer is live, 1 = released. Dispose and an initialization committing
    // concurrently with it can each see the other's write, so both may try to release the signer.
    private int _signerReleased;

    // The one initialization, published exactly once. Lazy defers starting it until a caller has won
    // the publish, so a losing caller neither re-reads the source nor opens a second signer.
    private Lazy<Task>? _initialization;

    // Tolerance on the not-before end of the signing key's validity window, and on that end only.
    // No relying party can observe a key's NotBefore — it is not a JWK member (RFC 7517 §4) and no
    // certificate is published anywhere — so signing a few minutes "early" is undetectable and
    // harmless, while a host clock trailing the machine that minted the credential would otherwise
    // turn a correct deployment into a hard startup failure. Fixed and non-configurable: an operator
    // knob here would only ever be turned up to work around a broken clock. The expiry end has a real
    // observer, every relying party validating a token, and stays exact.
    private static readonly TimeSpan NotBeforeGrace = TimeSpan.FromMinutes(5);

    /// <summary>
    /// Initialises a <see cref="SigningKeyRing"/> over <paramref name="source"/>. Call
    /// <see cref="EnsureInitializedAsync"/> (done automatically at host startup by
    /// <see cref="SigningKeyRingActivator"/>) before using <see cref="Current"/> or
    /// <see cref="SignAsync{TState}"/>.
    /// </summary>
    /// <param name="source">
    /// The signing key source to read once. This constructor takes ownership: the ring disposes
    /// <paramref name="source"/> once, at shutdown.
    /// </param>
    /// <param name="timeProvider">Used to evaluate the signing key's validity window at initialization time.</param>
    /// <exception cref="ArgumentNullException">
    /// Thrown when <paramref name="source"/> or <paramref name="timeProvider"/> is
    /// <see langword="null"/>.
    /// </exception>
    internal SigningKeyRing(ISigningKeySource source, TimeProvider timeProvider)
    {
        ArgumentNullException.ThrowIfNull(source);
        ArgumentNullException.ThrowIfNull(timeProvider);

        _source = source;
        _timeProvider = timeProvider;
    }

    /// <summary>
    /// Gets the currently active key set.
    /// </summary>
    /// <exception cref="InvalidOperationException">
    /// Thrown when the ring has not yet completed startup initialization.
    /// </exception>
    public SigningKeySet Current =>
        _binding?.KeySet ?? throw new InvalidOperationException(
            $"{nameof(SigningKeyRing)} has not completed startup initialization yet.");

    /// <summary>
    /// Gets the currently active key set, or <see langword="null"/> when the ring has not yet
    /// completed startup initialization — lets a health check report "not initialized" rather than
    /// throwing.
    /// </summary>
    internal SigningKeySet? CurrentOrNull => _binding?.KeySet;

    /// <summary>
    /// Resolves the current signing key, hands it to <paramref name="buildSigningInput"/> to form
    /// the exact bytes to sign, and signs whatever that callback returns.
    /// </summary>
    /// <typeparam name="TState">
    /// The type of <paramref name="state"/>, threaded through to <paramref name="buildSigningInput"/>
    /// without a closure allocation when it is a <see langword="static"/> lambda.
    /// </typeparam>
    /// <param name="state">Caller state passed through to <paramref name="buildSigningInput"/>.</param>
    /// <param name="buildSigningInput">
    /// Builds the exact bytes to sign from the resolved <see cref="SigningContext"/> and
    /// <paramref name="state"/>. Called synchronously, exactly once.
    /// </param>
    /// <param name="cancellationToken">A token to cancel the operation.</param>
    /// <returns>The signing input, the signature, and the key that signed it.</returns>
    /// <exception cref="InvalidOperationException">
    /// Thrown when the ring has not yet completed startup initialization.
    /// </exception>
    /// <exception cref="ArgumentNullException">
    /// Thrown when <paramref name="buildSigningInput"/> is <see langword="null"/>.
    /// </exception>
    /// <exception cref="ObjectDisposedException">
    /// Thrown when this instance has already been disposed.
    /// </exception>
    public async Task<SigningOutcome> SignAsync<TState>(
        TState state,
        Func<SigningContext, TState, ReadOnlyMemory<byte>> buildSigningInput,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(buildSigningInput);
        ObjectDisposedException.ThrowIf(_disposed != 0, this);

        var binding = _binding ?? throw new InvalidOperationException(
            $"{nameof(SigningKeyRing)} has not completed startup initialization yet.");

        var context = new SigningContext(binding.KeySet.SigningKey);
        var signingInput = buildSigningInput(context, state);

        // Copied before signing and after the signature comes back, so a pooled or reused buffer on
        // either side of ISigner.SignAsync can never disagree with the bytes SigningOutcome reports
        // as having been signed.
        var signingInputCopy = new ReadOnlyMemory<byte>(signingInput.ToArray());
        var signature = await binding.Signer.SignAsync(signingInputCopy, cancellationToken).ConfigureAwait(false);
        var signatureCopy = new ReadOnlyMemory<byte>(signature.ToArray());

        return new SigningOutcome(signingInputCopy, signatureCopy, binding.KeySet.SigningKey);
    }

    /// <inheritdoc/>
    void IDisposable.Dispose()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0)
            return;

        if (_binding is { } binding)
            ReleaseCommittedSigner(binding.Signer);

        if (_source is IDisposable disposable)
            disposable.Dispose();

        GC.SuppressFinalize(this);
    }

    /// <inheritdoc/>
    ValueTask IAsyncDisposable.DisposeAsync()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0)
            return ValueTask.CompletedTask;

        if (_binding is { } binding)
            ReleaseCommittedSigner(binding.Signer);

        return DisposeSourceAsync();
    }

    private async ValueTask DisposeSourceAsync()
    {
        if (_source is IAsyncDisposable asyncDisposable)
            await asyncDisposable.DisposeAsync().ConfigureAwait(false);
        else if (_source is IDisposable disposable)
            disposable.Dispose();

        GC.SuppressFinalize(this);
    }

    /// <summary>
    /// Rejects a signing key whose own validity window has not opened or has already closed.
    /// </summary>
    /// <remarks>
    /// Checked against <paramref name="signingKey"/> alone and never against the published set: a
    /// <c>Next</c> key whose window has not opened yet is the entire point of staging one, and a
    /// <c>Previous</c> key outliving its window is why it is still published.
    /// </remarks>
    private static void ValidateSigningKeyWindow(SigningKey signingKey, DateTimeOffset now)
    {
        // Written as a difference between the two instants rather than as `notBefore - Grace > now`.
        // The two are mathematically identical, but subtracting from notBefore underflows for a key
        // reported with a NotBefore at DateTimeOffset.MinValue — a plausible way for a third-party
        // source to spell "always valid" — throwing ArgumentOutOfRangeException out of startup
        // instead of the configuration failure this method exists to raise.
        if (signingKey.NotBefore is { } notBefore && notBefore - now > NotBeforeGrace)
        {
            throw new ZeeKayDaConfigurationException(
                new ZeeKayDaConfigurationFailure(
                    "signing.signing_key_not_yet_valid",
                    $"The Current signing key '{signingKey.Kid}' is not valid until {notBefore:O}. " +
                    "Configure it as Next until then, and leave the key it succeeds as Current."));
        }

        if (signingKey.ExpiresAt is { } expiresAt && expiresAt <= now)
        {
            throw new ZeeKayDaConfigurationException(
                new ZeeKayDaConfigurationFailure(
                    "signing.signing_key_expired",
                    $"The Current signing key '{signingKey.Kid}' expired at {expiresAt:O}. An " +
                    "expired signing key issues tokens no relying party will accept."));
        }
    }

    /// <summary>
    /// Reads the source, builds the key set, opens the signer, and self-tests it — once, however
    /// many times this is called.
    /// </summary>
    /// <remarks>
    /// Idempotent by design, and that is what lets a startup check depending on the key set ask for
    /// it rather than rely on running after <see cref="SigningKeyRingActivator"/>. A second
    /// call performs no second source read and opens no second signer; concurrent callers await the
    /// same work, which runs under the first caller's token, and observe the same outcome, including
    /// the same failure. A failed initialization stays failed: it runs at startup, where a failure
    /// aborts the host.
    /// </remarks>
    /// <param name="cancellationToken">A token that is signalled if the host is shutting down.</param>
    internal Task EnsureInitializedAsync(CancellationToken cancellationToken)
    {
        var candidate = new Lazy<Task>(() => InitializeCoreAsync(cancellationToken));
        return (Interlocked.CompareExchange(ref _initialization, candidate, null) ?? candidate).Value;
    }

    private async Task InitializeCoreAsync(CancellationToken cancellationToken)
    {
        var sourceKeys = await _source.ReadAsync(cancellationToken).ConfigureAwait(false);
        if (sourceKeys is null)
        {
            throw new ZeeKayDaConfigurationException(
                new ZeeKayDaConfigurationFailure(
                    "signing.null_source_key_set",
                    "The signing key source's ReadAsync returned null. ISigningKeySource.ReadAsync " +
                    "must never return null."));
        }

        var set = SigningKeySetBuilder.Build(sourceKeys);

        ValidateSigningKeyWindow(set.SigningKey, _timeProvider.GetUtcNow());

        var signer = await OpenSignerAsync(set.SigningKey, cancellationToken).ConfigureAwait(false);
        try
        {
            if (signer.Algorithm != set.SigningKey.Algorithm)
            {
                throw new ZeeKayDaConfigurationException(
                    new ZeeKayDaConfigurationFailure(
                        "signing.signer_algorithm_mismatch",
                        $"The signer opened for key '{set.SigningKey.Kid}' signs under {signer.Algorithm}, " +
                        $"but the key was reported with algorithm {set.SigningKey.Algorithm}."));
            }

            await SigningSelfTest.RunAsync(signer, set.SigningKey, cancellationToken).ConfigureAwait(false);
        }
        catch
        {
            // A throwing Dispose on a third-party signer must not replace the failure that actually
            // matters — the operator needs the algorithm mismatch or self-test failure, not whatever
            // went wrong while cleaning up after it.
            DisposeQuietly(signer);
            throw;
        }

        // A full fence, paired with Dispose's Interlocked.Exchange on _disposed: whichever runs
        // second sees the other's write, so a racing Dispose can never leave the signer open.
        Interlocked.Exchange(ref _binding, new SignerBinding(signer, set));

        // Dispose() may have run concurrently with the work above, between this instance being
        // constructed and _binding being committed. Re-check now rather than leaving a live signer
        // handle reachable behind a ring that has already reported itself disposed.
        if (Volatile.Read(ref _disposed) != 0)
            ReleaseCommittedSigner(signer);
    }

    private void ReleaseCommittedSigner(ISigner signer)
    {
        if (Interlocked.Exchange(ref _signerReleased, 1) == 0)
            DisposeQuietly(signer);
    }

    /// <summary>
    /// Disposes a signer on a failure path, swallowing anything its own <c>Dispose</c> throws so the
    /// original failure is the one that reaches the operator.
    /// </summary>
    private static void DisposeQuietly(ISigner signer)
    {
        try
        {
            signer.Dispose();
        }
        catch
        {
            // Intentionally swallowed: we are already unwinding a more important failure.
        }
    }

    private async ValueTask<ISigner> OpenSignerAsync(SigningKey signingKey, CancellationToken cancellationToken)
    {
        ISigner? signer;
        try
        {
            signer = await _source.CreateSignerAsync(signingKey.SourceId, cancellationToken).ConfigureAwait(false);
        }
        catch (ZeeKayDaConfigurationException)
        {
            // A source's own configuration exception already carries a stable, published code —
            // absorb it verbatim rather than flattening it into signing.signer_unavailable.
            throw;
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            // The exception TYPE is named, never ex.Message. An arbitrary underlying provider
            // exception may carry credential material (a request URL, an auth header) that
            // ZeeKayDaConfigurationFailure.Message — a plain string on public API surface — cannot
            // redact. The root cause stays available to operators as InnerException.
            throw new ZeeKayDaConfigurationException(
                new ZeeKayDaConfigurationFailure(
                    "signing.signer_unavailable",
                    $"The signer for key '{signingKey.SourceId.Value}' could not be opened: " +
                    $"{ex.GetType().FullName}. See the inner exception for the root cause."),
                ex);
        }

        if (signer is null)
        {
            throw new ZeeKayDaConfigurationException(
                new ZeeKayDaConfigurationFailure(
                    "signing.null_signer",
                    $"The signing key source's CreateSignerAsync returned null for key " +
                    $"'{signingKey.SourceId.Value}'. ISigningKeySource.CreateSignerAsync must never " +
                    "return null."));
        }

        return signer;
    }

    private sealed record SignerBinding(ISigner Signer, SigningKeySet KeySet);
}
