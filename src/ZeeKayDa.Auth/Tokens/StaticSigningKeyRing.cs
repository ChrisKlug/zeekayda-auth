namespace ZeeKayDa.Auth.Tokens;

/// <summary>
/// The shipped <see cref="ISigningKeyRing"/>: reads its <see cref="ISigningKeySource"/> exactly
/// once at startup, builds the key set, opens and self-tests the signer, then never reads again.
/// </summary>
/// <remarks>
/// Owns the one <see cref="ISigner"/> it opens for the process lifetime and disposes it once, at
/// shutdown — a consumer of <see cref="ISigningKeyRing"/> never receives it and never disposes it.
/// Also owns the <see cref="ISigningKeySource"/> it was constructed over: nothing else in the
/// container holds a reference to it, so the ring disposes it once, at shutdown, normally after the
/// signer — via <see cref="IDisposable.Dispose"/> or <see cref="IAsyncDisposable.DisposeAsync"/>,
/// whichever the host calls. The one exception is disposal racing <see cref="ISigningKeyRing.EnsureInitializedAsync"/>
/// before the signer has committed, in which case the source is disposed first. A polling
/// implementation can be added behind the same interface later without changing any consumer.
/// </remarks>
public sealed class StaticSigningKeyRing : ISigningKeyRing, IDisposable, IAsyncDisposable
{
    private readonly ISigningKeySource _source;
    private readonly TimeProvider _timeProvider;

    // The signing key set and the signer opened for it are read and written together, exactly once,
    // via Interlocked.CompareExchange — never as two independently-updated fields — so a consumer
    // can never observe one without the other, and initialization can only ever commit once.
    private SignerBinding? _binding;

    // 0 = live, 1 = disposed. int so Interlocked.Exchange makes the transition atomic.
    private int _disposed;

    // The in-flight or completed initialization, committed exactly once via CompareExchange. This
    // guards the ENTRY to initialization, where _binding guards only its commit: without it, a
    // second caller re-read the source and opened a second signer before discovering it had lost
    // the race. Startup checks that need the key set ask for it rather than assuming they run in a
    // position where it already exists, so no check's correctness depends on registration order.
    private Task? _initialization;

    // Tolerance on the not-before end of the signing key's validity window, and on that end only.
    // No relying party can observe a key's NotBefore — it is not a JWK member (RFC 7517 §4) and no
    // certificate is published anywhere — so signing a few minutes "early" is undetectable and
    // harmless, while a host clock trailing the machine that minted the credential would otherwise
    // turn a correct deployment into a hard startup failure. Fixed and non-configurable: an operator
    // knob here would only ever be turned up to work around a broken clock. The expiry end has a real
    // observer, every relying party validating a token, and stays exact.
    private static readonly TimeSpan NotBeforeGrace = TimeSpan.FromMinutes(5);

    /// <summary>
    /// Initialises a <see cref="StaticSigningKeyRing"/> over <paramref name="source"/>. Call
    /// <see cref="ISigningKeyRing.EnsureInitializedAsync"/> (done automatically at host startup by
    /// <see cref="SigningKeyRingStartupVerifier"/>) before using <see cref="Current"/> or
    /// <see cref="SignAsync{TState}"/>.
    /// </summary>
    /// <param name="source">
    /// The signing key source to read once. This constructor takes ownership: the ring disposes
    /// <paramref name="source"/> once, at shutdown, normally after the signer it opened — the one
    /// exception is disposal racing initialization before the signer has committed, in which case
    /// the source is disposed first.
    /// </param>
    /// <param name="timeProvider">Used to evaluate the signing key's validity window at initialization time.</param>
    /// <exception cref="ArgumentNullException">
    /// Thrown when <paramref name="source"/> or <paramref name="timeProvider"/> is
    /// <see langword="null"/>.
    /// </exception>
    /// <exception cref="ArgumentException">
    /// Thrown when <paramref name="source"/> implements <see cref="IAsyncDisposable"/> without also
    /// implementing <see cref="IDisposable"/>. The ring cannot know whether the host will dispose the
    /// service provider synchronously or asynchronously, so that shape can never be disposed safely.
    /// </exception>
    public StaticSigningKeyRing(ISigningKeySource source, TimeProvider timeProvider)
    {
        ArgumentNullException.ThrowIfNull(source);
        ArgumentNullException.ThrowIfNull(timeProvider);

        if (source is IAsyncDisposable && source is not IDisposable)
        {
            throw new ArgumentException(
                $"'{source.GetType().FullName}' implements {nameof(IAsyncDisposable)} but not " +
                $"{nameof(IDisposable)}. The ring that owns this source cannot know whether the host " +
                $"will dispose the service provider synchronously or asynchronously, so implement " +
                $"{nameof(IDisposable)} as well.", nameof(source));
        }

        _source = source;
        _timeProvider = timeProvider;
    }

    /// <inheritdoc/>
    public SigningKeySet Current =>
        _binding?.KeySet ?? throw new InvalidOperationException(
            $"{nameof(StaticSigningKeyRing)} has not completed startup initialization yet.");

    /// <inheritdoc/>
    /// <exception cref="ArgumentNullException">
    /// Thrown when <paramref name="buildSigningInput"/> is <see langword="null"/>.
    /// </exception>
    /// <exception cref="ObjectDisposedException">
    /// Thrown when this instance has already been disposed.
    /// </exception>
    public async ValueTask<SigningOutcome> SignAsync<TState>(
        TState state,
        Func<SigningContext, TState, ReadOnlyMemory<byte>> buildSigningInput,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(buildSigningInput);
        ObjectDisposedException.ThrowIf(_disposed != 0, this);

        var binding = _binding ?? throw new InvalidOperationException(
            $"{nameof(StaticSigningKeyRing)} has not completed startup initialization yet.");

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
            DisposeQuietly(binding.Signer);

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
            DisposeQuietly(binding.Signer);

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

    ValueTask ISigningKeyRing.EnsureInitializedAsync(CancellationToken cancellationToken)
    {
        // Already done: no allocation, no await, no second read.
        if (Volatile.Read(ref _binding) is not null)
            return ValueTask.CompletedTask;

        var started = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var inFlight = Interlocked.CompareExchange(ref _initialization, started.Task, null);

        // Someone else owns this initialization: await theirs rather than starting a second one.
        // They observe the same outcome, including the same failure.
        if (inFlight is not null)
            return new ValueTask(inFlight);

        return new ValueTask(RunInitializationAsync(started, cancellationToken));
    }

    /// <summary>
    /// Performs the one initialization this ring will ever do, completing <paramref name="started"/>
    /// so every concurrent caller observes the same outcome.
    /// </summary>
    /// <remarks>
    /// A failure is not reset for retry. Initialization runs at startup, where a failure aborts the
    /// host — leaving the failed task in place is what makes a second caller see the original
    /// failure rather than trigger a second attempt against a source that just refused.
    /// </remarks>
    private async Task RunInitializationAsync(TaskCompletionSource started, CancellationToken cancellationToken)
    {
        try
        {
            await InitializeCoreAsync(cancellationToken).ConfigureAwait(false);
            started.SetResult();
        }
        catch (Exception ex)
        {
            started.SetException(ex);
            throw;
        }
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

        if (Interlocked.CompareExchange(ref _binding, new SignerBinding(signer, set), null) is not null)
        {
            // Unreachable through EnsureInitializedAsync, which admits exactly one caller to this
            // method — kept as the structural guarantee that the binding is written once, so a
            // future second entry point cannot silently swap the key set out from under callers.
            DisposeQuietly(signer);
            return;
        }

        // Dispose() may have run concurrently with the work above, between this instance being
        // constructed and _binding being committed. Re-check now rather than leaving a live signer
        // handle reachable behind a ring that has already reported itself disposed.
        if (Volatile.Read(ref _disposed) != 0)
            DisposeQuietly(signer);
    }

    SigningKeySet? ISigningKeyRing.CurrentOrNull => _binding?.KeySet;

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
