using Microsoft.Extensions.Logging;
using ZeeKayDa.Auth.Logging;

namespace ZeeKayDa.Auth.Tokens;

/// <summary>
/// What every signing consumer depends on: the current <see cref="SigningKeySet"/>, and the ability
/// to sign with its signing key. Reads its <see cref="ISigningKeySource"/> once at startup, then
/// follows the clock: the key set changes, and a successor takes over signing, at the instants the
/// keys' own dates set, with no restart.
/// </summary>
/// <remarks>
/// <para>
/// <strong>Framework-owned.</strong> The constructor is <see langword="internal"/>: nothing outside
/// the framework can construct or substitute a ring, so no consumer can be handed a key set whose
/// signer skipped the self-test. A third party extends signing by implementing
/// <see cref="ISigningKeySource"/> instead.
/// </para>
/// <para>
/// <see cref="SignAsync{TState}"/>'s callback is synchronous by design: the caller cannot perform
/// I/O while the key is resolved, and the returned <see cref="SigningOutcome"/> makes header/key
/// disagreement unrepresentable rather than merely detected.
/// </para>
/// <para>
/// Every signer is self-tested before it signs. The startup signer failing stops the host. A
/// successor's signer failing when it is due to take over sets that key aside until a restart: it
/// stays published but never signs, the keys around it sign in its place, an Error is logged, and
/// <see cref="SigningKeyExpiryHealthCheck"/> reports Degraded.
/// </para>
/// <para>
/// Owns every <see cref="ISigner"/> it opens and disposes each once, at shutdown — a superseded
/// signer stays open until then, so a token being signed while its successor takes over never sees
/// it disposed. Also owns the <see cref="ISigningKeySource"/> it was constructed over: nothing else
/// holds a reference to it, so the ring disposes it once, at shutdown, after the signers — via
/// <see cref="IDisposable.Dispose"/> or <see cref="IAsyncDisposable.DisposeAsync"/>, whichever the
/// host calls.
/// </para>
/// </remarks>
public sealed class SigningKeyRing : IDisposable, IAsyncDisposable
{
    // A TimeProvider timer cannot wait longer than about 49 days; waking sooner and finding nothing
    // changed is harmless.
    private static readonly TimeSpan MaxWait = TimeSpan.FromDays(1);

    // How soon to try again after a transition failed for a reason no rule anticipated.
    private static readonly TimeSpan RetryDelay = TimeSpan.FromMinutes(1);

    // How long a successor's signer may take to open and self-test before it is set aside; a hung
    // open would otherwise hold the transition, and every later change, forever.
    private static readonly TimeSpan HandoverDeadline = TimeSpan.FromMinutes(1);

    private readonly ISigningKeySource _source;
    private readonly TimeProvider _timeProvider;
    private readonly SigningKeyOptions _options;
    private readonly SanitizingLogger<SigningKeyRing> _logger;
    private readonly CancellationTokenSource _shutdown = new();

    // Guards _signers, _timer and the transition from live to disposed.
    private readonly Lock _gate = new();
    private readonly Dictionary<string, ISigner> _signers = new(StringComparer.Ordinal);
    private ITimer? _timer;

    // The key set, the signer for its signing key and the timeline it was chosen from, replaced
    // together as one reference so a consumer can never observe one without the others.
    private SignerBinding? _binding;

    // 0 = live, 1 = disposed. Written under _gate, read without it.
    private int _disposed;

    // The one initialization, published exactly once. Lazy defers starting it until a caller has won
    // the publish, so a losing caller neither re-reads the source nor opens a second signer.
    private Lazy<Task>? _initialization;

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
    /// <param name="timeProvider">The clock that decides which key signs and which are published.</param>
    /// <param name="options">
    /// The timing rules that choose the signing key and the published keys, copied here so a later
    /// change to the caller's instance cannot reach the ring.
    /// </param>
    /// <param name="logger">Receives each rotation, and the warning when a key signs before it has been published for the lead time.</param>
    /// <exception cref="ArgumentNullException">
    /// Thrown when any argument is <see langword="null"/>.
    /// </exception>
    /// <exception cref="ArgumentException">
    /// Thrown when <paramref name="options"/> has no resolved <see cref="SigningKeyOptions.RetainRetiredKeysFor"/>.
    /// </exception>
    internal SigningKeyRing(
        ISigningKeySource source, TimeProvider timeProvider, SigningKeyOptions options, SanitizingLogger<SigningKeyRing> logger)
    {
        ArgumentNullException.ThrowIfNull(source);
        ArgumentNullException.ThrowIfNull(timeProvider);
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(logger);
        if (options.RetainRetiredKeysFor is null)
        {
            throw new ArgumentException(
                $"{nameof(SigningKeyOptions.RetainRetiredKeysFor)} must be resolved before the ring is constructed.",
                nameof(options));
        }

        _source = source;
        _timeProvider = timeProvider;
        _options = new SigningKeyOptions
        {
            LeadTime = options.LeadTime,
            RetainRetiredKeysFor = options.RetainRetiredKeysFor,
        };
        _logger = logger;
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
    /// Gets the listed keys and the rules over them, or <see langword="null"/> before startup
    /// initialization — what the health check looks ahead with.
    /// </summary>
    internal SigningKeyTimeline? TimelineOrNull => Volatile.Read(ref _binding)?.Timeline;

    /// <summary>
    /// Gets the key set and the timeline it was chosen from as one read, or <see langword="null"/>
    /// before startup initialization — what the health check judges.
    /// </summary>
    internal (SigningKeySet KeySet, SigningKeyTimeline Timeline)? StateOrNull =>
        Volatile.Read(ref _binding) is { } binding ? (binding.KeySet, binding.Timeline) : null;

    /// <summary>
    /// Gets the handover the timer started last, so a test can await it after advancing a fake clock.
    /// </summary>
    internal Task LastTransition { get; private set; } = Task.CompletedTask;

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
        if (!ReleaseSigners())
            return;

        if (_source is IDisposable disposable)
            disposable.Dispose();

        GC.SuppressFinalize(this);
    }

    /// <inheritdoc/>
    ValueTask IAsyncDisposable.DisposeAsync()
    {
        if (!ReleaseSigners())
            return ValueTask.CompletedTask;

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
    /// Marks the ring disposed, stops the timer, cancels a handover in flight, and disposes every
    /// signer opened so far. Returns <see langword="false"/> when the ring was already disposed.
    /// </summary>
    private bool ReleaseSigners()
    {
        List<ISigner> signers;
        lock (_gate)
        {
            if (_disposed != 0)
                return false;

            Volatile.Write(ref _disposed, 1);
            _timer?.Dispose();
            signers = [.. _signers.Values];
            _signers.Clear();
        }

        try
        {
            // Cancelled, never disposed: a handover in flight may still read its token, and a source
            // with no timer or linked token holds nothing to release.
            _shutdown.Cancel();
        }
        catch (AggregateException)
        {
            // A callback a source registered on the token threw. Shutdown must still release every
            // signer and the source, which nothing else will.
        }

        foreach (var signer in signers)
            DisposeQuietly(signer);

        return true;
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

        var timeline = SigningKeySetBuilder.Build(sourceKeys, _source.Algorithm, _options);
        var now = _timeProvider.GetUtcNow();
        if (timeline.DroppedKeyDueAt(now) is { } droppedSigningKey)
            throw new ZeeKayDaConfigurationException(droppedSigningKey.Failure);

        WarnAboutDroppedKeys(timeline);
        var set = timeline.At(now);

        if (set.SigningKey.ExpiresAt <= now)
        {
            throw new ZeeKayDaConfigurationException(
                new ZeeKayDaConfigurationFailure(
                    "signing.signing_key_expired",
                    $"Every listed signing key has expired; the last, '{set.SigningKey.SourceId.Value}', expired at " +
                    $"{set.SigningKey.ExpiresAt:O}. An expired key issues tokens no relying party will accept."));
        }

        var signer = await OpenTestedSignerAsync(set.SigningKey, cancellationToken).ConfigureAwait(false);

        Volatile.Write(ref _binding, new SignerBinding(signer, set, timeline));

        lock (_gate)
        {
            if (_disposed != 0)
            {
                // Dispose ran while the signer was being opened: it never saw this one, so release it
                // here rather than leave a live handle behind a ring that has already reported itself disposed.
                DisposeQuietly(signer);
                return;
            }

            // Created disarmed and armed only once assigned: a timer due at once may fire before
            // CreateTimer returns, and its transition re-arms through _timer.
            _signers.Add(set.SigningKey.Kid, signer);
            _timer = _timeProvider.CreateTimer(
                static state => ((SigningKeyRing)state!).OnTimer(), this, Timeout.InfiniteTimeSpan, Timeout.InfiniteTimeSpan);
        }

        // Scheduled from the instant the set was chosen: if a change passed while the signer
        // opened, the timer fires at once and the transition catches up.
        Rearm(WaitFrom(timeline, now, _timeProvider.GetUtcNow()));
        WarnIfNotEstablished(timeline, set.SigningKey, now);
    }

    // At most one transition runs at a time: the timer is one-shot and re-armed only when the
    // transition it started has finished.
    private void OnTimer() => LastTransition = TransitionAsync();

    /// <summary>
    /// Brings the key set up to the clock, handing signing over to a successor when one is due,
    /// then waits for the next instant the set can change. Never throws: a failure here has no
    /// caller to reach, so it is logged and the ring keeps its last working state.
    /// </summary>
    private async Task TransitionAsync()
    {
        DateTimeOffset evaluatedAt;
        try
        {
            // A handover takes time, and the clock may pass another change instant meanwhile, so
            // re-evaluate until the key due to sign is the one already signing.
            while (true)
            {
                var binding = Volatile.Read(ref _binding)!;
                var now = _timeProvider.GetUtcNow();
                evaluatedAt = now;
                var due = binding.Timeline.At(now);
                if (due.SigningKey.Kid == binding.KeySet.SigningKey.Kid)
                {
                    Volatile.Write(ref _binding, binding with { KeySet = due });
                    break;
                }

                await HandOverAsync(binding.KeySet.SigningKey, due.SigningKey).ConfigureAwait(false);
            }
        }
        catch (Exception) when (_shutdown.IsCancellationRequested)
        {
            return;
        }
        catch (Exception ex)
        {
            _logger.LogError(
                "The signing key ring failed to bring its key set up to date ({ExceptionType}); it keeps its last " +
                "key set and tries again in {RetryDelay}.",
                ex.GetType().FullName,
                RetryDelay);
            Rearm(RetryDelay);
            return;
        }

        Rearm(WaitFrom(Volatile.Read(ref _binding)!.Timeline, evaluatedAt, _timeProvider.GetUtcNow()));
    }

    private void Rearm(TimeSpan wait)
    {
        lock (_gate)
        {
            if (_disposed == 0)
                _timer!.Change(wait, Timeout.InfiniteTimeSpan);
        }
    }

    /// <summary>
    /// Opens and self-tests the signer for <paramref name="successor"/>, reusing one opened earlier,
    /// and makes it the signer. On failure the successor is set aside until a restart instead.
    /// </summary>
    private async Task HandOverAsync(SigningKey current, SigningKey successor)
    {
        ISigner? signer;
        lock (_gate)
            _signers.TryGetValue(successor.Kid, out signer);

        if (signer is null)
        {
            using var abandon = CancellationTokenSource.CreateLinkedTokenSource(_shutdown.Token);
            var opening = OpenTestedSignerAsync(successor, abandon.Token).AsTask();
            try
            {
                // Waited on with the ring's clock, not only the token: a source may ignore cancellation.
                signer = await opening.WaitAsync(HandoverDeadline, _timeProvider, _shutdown.Token).ConfigureAwait(false);
            }
            catch (Exception ex) when (!_shutdown.IsCancellationRequested)
            {
                if (ex is TimeoutException)
                {
                    abandon.Cancel();
                    DisposeIfItOpensLate(opening);
                }

                SetAside(current, successor, ex);
                return;
            }

            if (!TryKeep(successor, signer))
                throw new OperationCanceledException(_shutdown.Token);
        }

        var timeline = Volatile.Read(ref _binding)!.Timeline;
        var now = _timeProvider.GetUtcNow();
        var set = timeline.At(now);

        // The clock may have moved on while the signer opened; the caller's loop then hands over to
        // whichever key is due now, and this signer stays cached for if its turn comes again.
        if (set.SigningKey.Kid != successor.Kid)
            return;

        Volatile.Write(ref _binding, new SignerBinding(signer, set, timeline));

        _logger.LogInformation(
            "Key {Kid} ({SourceKeyId}) now signs, taking over from {PreviousKid} ({PreviousSourceKeyId}).",
            successor.Kid, successor.SourceId.Value, current.Kid, current.SourceId.Value);
        WarnIfNotEstablished(timeline, successor, now);
    }

    /// <summary>
    /// Sets <paramref name="successor"/> aside on the timeline, so it stays published but never
    /// signs and the rules carry on with the keys around it; the health check reads it from there.
    /// </summary>
    private void SetAside(SigningKey current, SigningKey successor, Exception failure)
    {
        var binding = Volatile.Read(ref _binding)!;
        Volatile.Write(ref _binding, binding with { Timeline = binding.Timeline.SettingAside(successor.Kid) });

        var reason = failure switch
        {
            ZeeKayDaConfigurationException configuration => configuration.AggregatedFailures[0].Code,
            TimeoutException => $"did not open within {HandoverDeadline}",
            _ => failure.GetType().FullName,
        };
        _logger.LogError(
            failure,
            "Key {Kid} ({SourceKeyId}) is due to sign, but its signer failed ({Failure}); it is set aside until a " +
            "restart and {CurrentKid} ({CurrentSourceKeyId}) signs on. Fix the key and restart.",
            successor.Kid, successor.SourceId.Value, reason, current.Kid, current.SourceId.Value);
    }

    private static void DisposeIfItOpensLate(Task<ISigner> opening) =>
        _ = opening.ContinueWith(
            static task =>
            {
                if (task.IsCompletedSuccessfully)
                    DisposeQuietly(task.Result);
            },
            CancellationToken.None,
            TaskContinuationOptions.ExecuteSynchronously,
            TaskScheduler.Default);

    /// <summary>
    /// Adds a freshly opened signer to those disposed at shutdown, or disposes it at once when
    /// shutdown has already run.
    /// </summary>
    private bool TryKeep(SigningKey key, ISigner signer)
    {
        lock (_gate)
        {
            if (_disposed == 0)
            {
                _signers.Add(key.Kid, signer);
                return true;
            }
        }

        DisposeQuietly(signer);
        return false;
    }

    private void WarnAboutDroppedKeys(SigningKeyTimeline timeline)
    {
        foreach (var drop in timeline.Dropped)
        {
            _logger.LogWarning(
                "Signing key {SourceKeyId} was dropped and is neither published nor used to sign: [{FailureCode}] {Reason}",
                drop.Key.Id.Value, drop.Failure.Code, drop.Failure.Message);
        }

        if (timeline.CoverageCutShortTo() is { } usableUntil)
        {
            _logger.LogWarning(
                "With the dropped signing keys gone, the last usable key expires at {UsableUntil}, sooner than the " +
                "listed keys would have. Fix or replace the dropped keys before then.",
                usableUntil);
        }
    }

    private void WarnIfNotEstablished(SigningKeyTimeline timeline, SigningKey signingKey, DateTimeOffset now)
    {
        if (timeline.IsEstablished(signingKey, now))
            return;

        _logger.LogWarning(
            "Signing with key {Kid} ({SourceKeyId}), published less than the lead time of {LeadTime} ago. " +
            "Relying parties with a cached key set may reject its tokens until they refresh.",
            signingKey.Kid, signingKey.SourceId.Value, timeline.LeadTime);
    }

    /// <summary>
    /// The wait until the first change after <paramref name="evaluatedAt"/>, the instant the
    /// committed set was chosen for — measured against <paramref name="now"/>, so a change that
    /// passed since is not skipped but fires at once.
    /// </summary>
    private static TimeSpan WaitFrom(SigningKeyTimeline timeline, DateTimeOffset evaluatedAt, DateTimeOffset now)
    {
        var next = timeline.NextChangeAfter(evaluatedAt);
        if (next == DateTimeOffset.MaxValue)
            return Timeout.InfiniteTimeSpan;

        var remaining = next - now;
        if (remaining <= TimeSpan.Zero)
            return TimeSpan.Zero;

        // Rounded up: a timer truncates to whole milliseconds, and waking a fraction early would
        // only find nothing changed and re-arm for the remainder.
        var wait = TimeSpan.FromMilliseconds(Math.Ceiling(remaining.TotalMilliseconds));
        return wait < MaxWait ? wait : MaxWait;
    }

    private async ValueTask<ISigner> OpenTestedSignerAsync(SigningKey key, CancellationToken cancellationToken)
    {
        var signer = await OpenSignerAsync(key, cancellationToken).ConfigureAwait(false);
        try
        {
            await SigningSelfTest.RunAsync(signer, key, cancellationToken).ConfigureAwait(false);
        }
        catch
        {
            // A throwing Dispose on a third-party signer must not replace the failure that actually
            // matters — the operator needs the self-test failure, not whatever went wrong while
            // cleaning up after it.
            DisposeQuietly(signer);
            throw;
        }

        return signer;
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

    /// <summary>The signer, the key set it signs for, and the timeline that set was chosen from.</summary>
    private sealed record SignerBinding(ISigner Signer, SigningKeySet KeySet, SigningKeyTimeline Timeline);
}
