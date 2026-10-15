using System.Security.Cryptography;
using Microsoft.Extensions.Logging;
using ZeeKayDa.Auth.Logging;
using static ZeeKayDa.Auth.Tokens.SigningKeyRingState;

namespace ZeeKayDa.Auth.Tokens;

/// <summary>
/// What every signing consumer depends on: the current <see cref="SigningKeySet"/>, signing with its
/// signing key, and verifying a signature against any key its source lists. Reads its
/// <see cref="ISigningKeySource"/> at startup and every <see cref="SigningKeyOptions.RefreshInterval"/>,
/// and follows the keys' own dates in between, with no restart.
/// </summary>
/// <remarks>
/// <para>
/// <strong>Framework-owned.</strong> The constructor is <see langword="internal"/>, so no consumer can be
/// handed a key set whose signer skipped the self-test. Extend signing by implementing
/// <see cref="ISigningKeySource"/> instead.
/// </para>
/// <para>
/// <see cref="SignAsync{TState}"/>'s callback is synchronous by design: the caller cannot perform
/// I/O while the key is resolved, and the returned <see cref="SigningOutcome"/> makes header/key
/// disagreement unrepresentable rather than merely detected.
/// </para>
/// <para>
/// A read that fails keeps the last list. A read listing no keys, or a list that is ambiguous, stops
/// signing: <see cref="SigningKeySet.SigningKey"/> is <see langword="null"/>, nothing is published or
/// verifies, and <see cref="SignAsync{TState}"/> throws until a later read lists keys the ring can use.
/// </para>
/// <para>
/// Every signer is self-tested before it signs. When the key due to sign cannot — its signer fails to
/// open or self-test, or the key was dropped for bad material or dates — the keys around it sign in its
/// place, an Error is logged, and <see cref="SigningKeyExpiryHealthCheck"/> reports Degraded. A key that
/// still cannot sign once the key it replaces is superseded never takes over, however it is fixed. Only
/// startup refuses: its signer failing, or the key due now having been dropped, stops the host.
/// </para>
/// <para>
/// Owns every <see cref="ISigner"/> it opens and disposes each once: a full
/// <see cref="SigningKeyOptions.RefreshInterval"/> after it stops signing, or at shutdown. Also owns its
/// <see cref="ISigningKeySource"/>, disposed at shutdown after the signers.
/// </para>
/// </remarks>
public sealed class SigningKeyRing : IDisposable, IAsyncDisposable
{
    // A TimeProvider timer cannot wait longer than about 49 days; waking sooner and finding nothing
    // changed is harmless.
    private static readonly TimeSpan MaxWait = TimeSpan.FromDays(1);

    // How soon to try again after a transition failed for a reason no rule anticipated.
    private static readonly TimeSpan RetryDelay = TimeSpan.FromMinutes(1);

    // How long a source read, or a successor's signer opening and self-testing, may take before it
    // counts as failed; a hung call would otherwise hold the transition, and every later change, forever.
    private static readonly TimeSpan SourceDeadline = TimeSpan.FromMinutes(1);

    private readonly ISigningKeySource _source;
    private readonly TimeProvider _timeProvider;
    private readonly SigningKeyOptions _options;
    private readonly SanitizingLogger<SigningKeyRing> _logger;
    private readonly CancellationTokenSource _shutdown = new();

    // Guards _signers, _timer and the transition from live to disposed.
    private readonly Lock _gate = new();
    private readonly Dictionary<SignerId, ISigner> _signers = [];
    private ITimer? _timer;

    // Read once, at initialization: a source whose getter changes cannot change the server's algorithm.
    private SigningAlgorithm _algorithm;

    // Touched only by initialization and the transition, which never overlap.
    private DateTimeOffset _nextReadAt;
    private readonly Dictionary<SignerId, DateTimeOffset> _idleSince = [];

    // Keys that failed when due or were ever dropped, and have not signed since: such a key never takes
    // over once its predecessor is superseded. By source id, since a dropped key may have no kid.
    private readonly HashSet<SourceKeyId> _failed = [];

    // Renewals of the signing key pair whose signer failed since the last read: the signer of the entry
    // they renew signs on, and the next read tries them again.
    private readonly HashSet<SignerId> _renewalsFailed = [];

    // A read abandoned at its deadline may still be running; no second one starts on the source until it ends.
    private Task? _reading;

    private SigningKeyRingState? _state;

    // 0 = live, 1 = disposed. Written under _gate, read without it.
    private int _disposed;

    // The one initialization, published exactly once. Lazy defers starting it until a caller has won
    // the publish, so a losing caller neither re-reads the source nor opens a second signer.
    private Lazy<Task>? _initialization;

    /// <summary>
    /// Initialises a ring over <paramref name="source"/>; <see cref="EnsureInitializedAsync"/> must complete before use.
    /// </summary>
    /// <param name="source">The signing key source to read, owned and disposed by the ring.</param>
    /// <param name="timeProvider">The clock that decides which key signs and which are published.</param>
    /// <param name="options">The timing rules, copied so a later change to the caller's instance cannot reach the ring.</param>
    /// <param name="logger">Receives rotations and key warnings.</param>
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
            RefreshInterval = options.RefreshInterval,
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
        Volatile.Read(ref _state)?.KeySet ?? throw new InvalidOperationException(
            $"{nameof(SigningKeyRing)} has not completed startup initialization yet.");

    /// <summary>The current key set, or <see langword="null"/> before startup initialization.</summary>
    internal SigningKeySet? CurrentOrNull => Volatile.Read(ref _state)?.KeySet;

    /// <summary>The listed keys and the rules over them, or <see langword="null"/> before startup initialization.</summary>
    internal SigningKeyTimeline? TimelineOrNull => Volatile.Read(ref _state) is { } state ? TimelineOf(state) : null;

    /// <summary>What the ring is doing, or <see langword="null"/> before startup initialization.</summary>
    internal SigningKeyRingState? StateOrNull => Volatile.Read(ref _state);

    /// <summary>The handover the timer started last.</summary>
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
    /// <paramref name="state"/>. Called synchronously, exactly once. The bytes it returns are signed
    /// verbatim under the framework's key, so they must be built from the token the framework is
    /// issuing, never decided by request data.
    /// </param>
    /// <param name="cancellationToken">A token to cancel the operation.</param>
    /// <returns>The signing input, the signature, and the key that signed it.</returns>
    /// <exception cref="InvalidOperationException">
    /// Thrown when the ring has not yet completed startup initialization, or when signing has stopped.
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

        var current = Volatile.Read(ref _state) ?? throw new InvalidOperationException(
            $"{nameof(SigningKeyRing)} has not completed startup initialization yet.");

        if (current is not Signing signing)
        {
            throw new InvalidOperationException(
                $"Signing has stopped ({ReasonOf(current)}): the signing key source lists no key the ring can sign with yet.");
        }

        var signingKey = signing.SigningKey;
        var context = new SigningContext(signingKey);
        var signingInput = buildSigningInput(context, state);

        // Copied both ways, so a reused buffer can never disagree with the bytes SigningOutcome reports.
        var signingInputCopy = new ReadOnlyMemory<byte>(signingInput.ToArray());
        var signature = await signing.Signer.SignAsync(signingInputCopy, cancellationToken).ConfigureAwait(false);
        var signatureCopy = new ReadOnlyMemory<byte>(signature.ToArray());

        return new SigningOutcome(signingInputCopy, signatureCopy, signingKey);
    }

    /// <summary>
    /// Verifies <paramref name="signature"/> over <paramref name="signingInput"/> with the listed key
    /// whose <see cref="SigningKey.Kid"/> is <paramref name="kid"/>, under that key's own algorithm.
    /// </summary>
    /// <remarks>
    /// Every key the source lists verifies, published or not: a token stays verifiable for as long as
    /// the key that signed it is listed. It stops verifying at the first successful read that no
    /// longer lists the key; a read that fails keeps the last list. What else makes a token valid, its
    /// lifetime included, is the caller's to judge.
    /// </remarks>
    /// <param name="kid">The key the token names.</param>
    /// <param name="signingInput">The exact bytes that were signed.</param>
    /// <param name="signature">The signature to verify.</param>
    /// <returns>
    /// The key that verified, or <see langword="null"/> when no listed key has <paramref name="kid"/>
    /// or the signature does not verify. Which of the two is never reported.
    /// </returns>
    /// <exception cref="ArgumentNullException">
    /// Thrown when <paramref name="kid"/> is <see langword="null"/>.
    /// </exception>
    /// <exception cref="InvalidOperationException">
    /// Thrown when the ring has not yet completed startup initialization.
    /// </exception>
    /// <exception cref="ObjectDisposedException">
    /// Thrown when this instance has already been disposed.
    /// </exception>
    public SigningKey? Verify(string kid, ReadOnlySpan<byte> signingInput, ReadOnlySpan<byte> signature)
    {
        ArgumentNullException.ThrowIfNull(kid);
        ObjectDisposedException.ThrowIf(_disposed != 0, this);

        var state = Volatile.Read(ref _state) ?? throw new InvalidOperationException(
            $"{nameof(SigningKeyRing)} has not completed startup initialization yet.");

        var key = TimelineOf(state)?.Keys.FirstOrDefault(listed => string.Equals(listed.Kid, kid, StringComparison.Ordinal));
        return key is not null && HasValidSignature(key, signingInput, signature) ? key : null;
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

    /// <summary>Marks the ring disposed and releases the timer and signers; <see langword="false"/> when already disposed.</summary>
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

        // Cancelled, never disposed: a handover in flight may still read its token, and a source
        // with no timer or linked token holds nothing to release.
        CancelQuietly(_shutdown);

        foreach (var signer in signers)
            DisposeQuietly(signer);

        return true;
    }

    /// <summary>
    /// Reads the source, builds the key set, and opens and self-tests the signer — once, however often it is
    /// called, so a startup check can ask for the key set. A failed initialization stays failed.
    /// </summary>
    /// <param name="cancellationToken">A token that is signalled if the host is shutting down.</param>
    internal Task EnsureInitializedAsync(CancellationToken cancellationToken)
    {
        var candidate = new Lazy<Task>(() => InitializeCoreAsync(cancellationToken));
        return (Interlocked.CompareExchange(ref _initialization, candidate, null) ?? candidate).Value;
    }

    private async Task InitializeCoreAsync(CancellationToken cancellationToken)
    {
        var listing = await _source.ReadAsync(cancellationToken).ConfigureAwait(false);
        if (listing is null)
        {
            throw new ZeeKayDaConfigurationException(
                new ZeeKayDaConfigurationFailure(
                    "signing.null_source_key_set",
                    "The signing key source's ReadAsync returned null. ISigningKeySource.ReadAsync " +
                    "must never return null."));
        }

        _algorithm = _source.Algorithm;
        var timeline = SigningKeySetBuilder.Build(listing, _algorithm, _options);
        var now = _timeProvider.GetUtcNow();
        _nextReadAt = TokenLifetimes.ExpiresAt(now, _options.RefreshInterval);
        if (timeline.DroppedKeyDueAt(now) is { } droppedSigningKey)
            throw new ZeeKayDaConfigurationException(droppedSigningKey.Failure);

        RecordDroppedKeys(timeline);
        WarnAboutDroppedKeys(timeline, previous: null);
        LogMergedKeys(timeline, previous: null);
        var set = timeline.At(now);
        var signingKey = timeline.SigningKeyAt(now);

        if (signingKey.ExpiresAt <= now)
        {
            _logger.LogError(
                "Every listed signing key has expired; the last to expire, {Kid} ({SourceKeyId}), expired at " +
                "{ExpiresAt} and signs on until a read lists an unexpired key. List a fresh key.",
                signingKey.Kid, signingKey.SourceId.Value, signingKey.ExpiresAt);
        }

        var signer = await OpenTestedSignerAsync(signingKey, cancellationToken).ConfigureAwait(false);

        Volatile.Write(ref _state, new Signing(signer, set, timeline));

        lock (_gate)
        {
            if (_disposed != 0)
            {
                // Dispose ran while the signer was opening and never saw it.
                DisposeQuietly(signer);
                return;
            }

            // Created disarmed and armed only once assigned: a timer due at once may fire before
            // CreateTimer returns, and its transition re-arms through _timer.
            _signers.Add(SignerId.Of(signingKey), signer);
            _timer = _timeProvider.CreateTimer(
                static state => ((SigningKeyRing)state!).OnTimer(), this, Timeout.InfiniteTimeSpan, Timeout.InfiniteTimeSpan);
        }

        // Scheduled from the instant the set was chosen: if a change passed while the signer
        // opened, the timer fires at once and the transition catches up.
        Rearm(NextWait(timeline, now));
        WarnIfNotEstablished(timeline, signingKey, now);
    }

    // At most one transition runs at a time: the timer is one-shot and re-armed only when the
    // transition it started has finished.
    private void OnTimer() => LastTransition = TransitionAsync();

    /// <summary>Re-reads the source when due, follows the clock, and re-arms. Never throws: a failure has no caller.</summary>
    private async Task TransitionAsync()
    {
        DateTimeOffset evaluatedAt;
        var reads = _timeProvider.GetUtcNow() >= _nextReadAt;
        try
        {
            if (reads)
                await RefreshAsync().ConfigureAwait(false);

            evaluatedAt = await FollowTheClockAsync().ConfigureAwait(false);
        }
        catch (Exception) when (_shutdown.IsCancellationRequested)
        {
            return;
        }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        {
            _logger.LogError(
                "The signing key ring failed to bring its key set up to date ({ExceptionType}); it keeps its last " +
                "key set and tries again in {RetryDelay}.",
                ex.GetType().FullName,
                RetryDelay);
            Rearm(RetryDelay);
            return;
        }
        finally
        {
            // A transition that fails every time must not keep a retired key resident indefinitely.
            if (reads && !_shutdown.IsCancellationRequested)
                ReleaseIdleSigners();
        }

        Rearm(NextWait(TimelineOf(Volatile.Read(ref _state)!), evaluatedAt));
    }

    /// <summary>Hands over until the key due to sign is the one signing; returns the instant the committed set was chosen for.</summary>
    private async Task<DateTimeOffset> FollowTheClockAsync()
    {
        while (true)
        {
            var state = Volatile.Read(ref _state)!;
            var now = _timeProvider.GetUtcNow();
            if (TimelineOf(state) is not { } timeline)
                return now;

            var due = timeline.SigningKeyAt(now);
            var signingKey = (state as Signing)?.SigningKey;
            if (state is Signing signing && SignerId.Of(due) == SignerId.Of(signing.SigningKey))
            {
                Volatile.Write(ref _state, signing with { KeySet = timeline.At(now) });
                return now;
            }

            if (state is Signing renewing && _renewalsFailed.Contains(SignerId.Of(due)))
            {
                Volatile.Write(ref _state, renewing with { KeySet = KeySetSignedBy(renewing.SigningKey, timeline, now) });
                return now;
            }

            await HandOverAsync(signingKey, due).ConfigureAwait(false);
        }
    }

    /// <summary>Reads the source and adopts what it lists, keeping the last list when the read fails.</summary>
    private async Task RefreshAsync()
    {
        var now = _timeProvider.GetUtcNow();
        _nextReadAt = TokenLifetimes.ExpiresAt(now, _options.RefreshInterval);
        _renewalsFailed.Clear();

        if (_reading is { IsCompleted: false })
        {
            KeepLastList("the previous read has not completed", failure: null);
            return;
        }

        SourceKeyListing? listing;
        try
        {
            listing = await ReadSourceAsync().ConfigureAwait(false);
        }
        catch (Exception ex) when (!_shutdown.IsCancellationRequested)
        {
            KeepLastList(Describe(ex), ex);
            return;
        }

        if (listing is null)
        {
            KeepLastList("signing.null_source_key_set", failure: null);
            return;
        }

        // Judged when the read completed: a key may have passed a cutoff while the source was read.
        now = _timeProvider.GetUtcNow();
        var previous = TimelineOf(Volatile.Read(ref _state)!);
        SigningKeyTimeline timeline;
        try
        {
            timeline = SigningKeySetBuilder.Build(listing, _algorithm, _options);
        }
        catch (ZeeKayDaConfigurationException ex)
        {
            StopSigning(ex.AggregatedFailures[0]);
            return;
        }

        RecordDroppedKeys(timeline);
        var droppedSigningKey = timeline.DroppedKeyDueAt(now);

        if (KeepingTooLateKeysAside(timeline, now) is not { } adopted)
        {
            StopSigning(new ZeeKayDaConfigurationFailure(
                "signing.no_usable_key",
                "Every listed key could not sign when due and is too late to take over now. List a fresh key."));
            return;
        }

        WarnAboutDroppedKeys(adopted, previous);
        if (droppedSigningKey is not null)
            LogDroppedKeySkipped(droppedSigningKey, adopted.SigningKeyAt(now));

        LogMergedKeys(adopted, previous);
        Volatile.Write(ref _state, Adopting(Volatile.Read(ref _state)!, adopted, now));
    }

    /// <summary>Records every dropped key, not only one due now: a key's whole due window may fall between two reads.</summary>
    private void RecordDroppedKeys(SigningKeyTimeline timeline)
    {
        foreach (var drop in timeline.Dropped)
            _failed.Add(drop.Id);
    }

    private void LogDroppedKeySkipped(DroppedKey dropped, SigningKey signsOn) =>
        _logger.LogError(
            "Key {SourceKeyId} is due to sign, but it was dropped: [{FailureCode}] {Reason} Key {Kid} ({SigningSourceKeyId}) " +
            "signs in its place. Fix the key; the next read tries it again, unless the key it would replace is " +
            "superseded by then, when only a fresh key can take over.",
            dropped.Id.Value, dropped.Failure.Code, dropped.Failure.Message, signsOn.Kid, signsOn.SourceId.Value);

    /// <summary>The state once <paramref name="timeline"/> is adopted; signing carries on only while its key is still listed.</summary>
    private SigningKeyRingState Adopting(SigningKeyRingState state, SigningKeyTimeline timeline, DateTimeOffset now)
    {
        var published = timeline.At(now).Published;
        switch (state)
        {
            case Signing signing when StillLists(timeline, signing.SigningKey)
                                      && timeline.Keys.FirstOrDefault(key => key.Kid == signing.SigningKey.Kid) is { } stillListed:
                // A renewal now opening the key pair under another source id signs once its handover opens it.
                var signingKey = SignerId.Of(stillListed) == SignerId.Of(signing.SigningKey) ? stillListed : signing.SigningKey;
                return signing with
                {
                    KeySet = KeySetSignedBy(signingKey, timeline, now),
                    Timeline = timeline,
                    ReadFailure = null,
                };

            case Signing signing:
                _logger.LogWarning(
                    "Key {Kid} ({SourceKeyId}) is no longer listed, so it stops signing; signing resumes once the key due " +
                    "to sign takes over.",
                    signing.SigningKey.Kid, signing.SigningKey.SourceId.Value);
                return new Resuming(new SigningKeySet(_algorithm, null, published), timeline, "signing.signing_key_unlisted")
                {
                    LastSignedKid = signing.SigningKey.Kid,
                };

            default:
                return new Resuming(new SigningKeySet(_algorithm, null, published), timeline, ReasonOf(state)!)
                {
                    LastSignedKid = (state as Resuming)?.LastSignedKid,
                };
        }
    }

    /// <summary>
    /// Whether <paramref name="timeline"/> lists <paramref name="key"/> under its own source id: a renewal under
    /// another id does not vouch for an entry the source removed.
    /// </summary>
    private static bool StillLists(SigningKeyTimeline timeline, SigningKey key) =>
        timeline.Keys.Any(listed => SignerId.Of(listed) == SignerId.Of(key))
        || timeline.Merged.Any(merged => merged.Key.Kid == key.Kid && merged.SourceIds.Contains(key.SourceId));

    /// <summary><paramref name="timeline"/>'s key set at <paramref name="now"/>, signed and published by <paramref name="signingKey"/>.</summary>
    private SigningKeySet KeySetSignedBy(SigningKey signingKey, SigningKeyTimeline timeline, DateTimeOffset now)
    {
        var published = timeline.At(now).Published;
        IReadOnlyList<SigningKey> withSigner = published.Any(key => key.Kid == signingKey.Kid)
            ? published
            : [.. published.Append(signingKey).Order(SigningKeySetBuilder.OldestFirst)];
        return new SigningKeySet(_algorithm, signingKey, withSigner);
    }

    private async Task<SourceKeyListing?> ReadSourceAsync()
    {
        using var abandon = CancellationTokenSource.CreateLinkedTokenSource(_shutdown.Token);

        // Run off the transition, and waited on with the ring's clock rather than the token alone:
        // a source may block synchronously or ignore cancellation.
        var reading = Task.Run(() => _source.ReadAsync(abandon.Token), CancellationToken.None);
        _reading = reading;
        try
        {
            return await reading.WaitAsync(SourceDeadline, _timeProvider, _shutdown.Token).ConfigureAwait(false);
        }
        catch
        {
            CancelQuietly(abandon);
            throw;
        }
    }

    /// <summary>Sets aside every failed key now too late to take over; <see langword="null"/> when no key could sign.</summary>
    private SigningKeyTimeline? KeepingTooLateKeysAside(SigningKeyTimeline timeline, DateTimeOffset now)
    {
        var signedLast = SignedLast(Volatile.Read(ref _state)!);
        SigningKeyTimeline? adopted = timeline;
        foreach (var key in timeline.Keys.Where(key => StaysAside(key, signedLast, timeline, now)))
            adopted = adopted?.SettingAside(key.Kid);

        return adopted;
    }

    /// <summary>
    /// Whether <paramref name="key"/> could not sign when due and is now too late to take over. Never the key
    /// pair that signs or signed last: taking over through another entry for it drops nothing from publication.
    /// </summary>
    private bool StaysAside(SigningKey key, string? signedLast, SigningKeyTimeline timeline, DateTimeOffset now) =>
        timeline.SourceIdsOf(key).Any(_failed.Contains) && key.Kid != signedLast && timeline.IsTooLateToTakeOver(key, now);

    private static string? SignedLast(SigningKeyRingState state) => state switch
    {
        Signing signing => signing.SigningKey.Kid,
        Resuming resuming => resuming.LastSignedKid,
        _ => null,
    };

    private void KeepLastList(string reason, Exception? failure)
    {
        Volatile.Write(ref _state, Volatile.Read(ref _state)! with { ReadFailure = reason });
        _logger.LogError(
            failure,
            "The signing key source could not be read ({Failure}); the ring keeps its last key list and reads again " +
            "in {RefreshInterval}.",
            reason,
            _options.RefreshInterval);
    }

    /// <summary>Stops signing and publishes nothing until a later read lists keys the ring can use.</summary>
    private void StopSigning(ZeeKayDaConfigurationFailure failure)
    {
        Volatile.Write(ref _state, new Stopped(SigningKeySet.Stopped(_algorithm), failure.Code));
        _logger.LogError(
            "Signing has stopped and no key is published: [{FailureCode}] {Reason} Signing resumes once the source " +
            "lists keys the ring can use.",
            failure.Code,
            failure.Message);
    }

    /// <summary>
    /// Disposes every signer idle for a full refresh interval, so a sign call that resolved one just before it
    /// stopped can finish with it.
    /// </summary>
    private void ReleaseIdleSigners()
    {
        var signing = (Volatile.Read(ref _state) as Signing)?.Signer;
        var now = _timeProvider.GetUtcNow();
        List<ISigner> released = [];
        lock (_gate)
        {
            foreach (var (id, signer) in _signers.ToList())
            {
                if (ReferenceEquals(signer, signing))
                {
                    _idleSince.Remove(id);
                }
                else if (!_idleSince.TryAdd(id, now) && now - _idleSince[id] >= _options.RefreshInterval)
                {
                    _idleSince.Remove(id);
                    _signers.Remove(id);
                    released.Add(signer);
                }
            }
        }

        foreach (var signer in released)
            DisposeQuietly(signer);
    }

    private void Rearm(TimeSpan wait)
    {
        lock (_gate)
        {
            if (_disposed == 0)
                _timer!.Change(wait, Timeout.InfiniteTimeSpan);
        }
    }

    /// <summary>Makes <paramref name="successor"/>'s signer the signer, unless the clock moved on or it is too late to take over.</summary>
    private async Task HandOverAsync(SigningKey? current, SigningKey successor)
    {
        if (await SignerForAsync(current, successor).ConfigureAwait(false) is not { } signer)
            return;

        var timeline = TimelineOf(Volatile.Read(ref _state)!)!;
        var now = _timeProvider.GetUtcNow();

        // The clock may have moved on while the signer opened; the caller's loop then hands over to
        // whichever key is due now, and this signer is released like any other that does not sign.
        if (SignerId.Of(timeline.SigningKeyAt(now)) != SignerId.Of(successor))
            return;

        // A retried key whose cutoff passed while its signer opened: its predecessor is superseded.
        if (StaysAside(successor, SignedLast(Volatile.Read(ref _state)!), timeline, now))
        {
            SetAside(current, successor, "too late to take over", failure: null);
            return;
        }

        _failed.ExceptWith(timeline.SourceIdsOf(successor));
        Volatile.Write(ref _state, new Signing(signer, timeline.At(now), timeline) { ReadFailure = _state!.ReadFailure });
        _idleSince.Remove(SignerId.Of(successor));
        if (current is not null)
            _idleSince[SignerId.Of(current)] = now;

        LogTakeover(current, successor);
        WarnIfNotEstablished(timeline, successor, now);
    }

    /// <summary>The cached or newly opened and self-tested signer; <see langword="null"/> when it failed and the key was set aside.</summary>
    private async Task<ISigner?> SignerForAsync(SigningKey? current, SigningKey successor)
    {
        lock (_gate)
        {
            if (_signers.TryGetValue(SignerId.Of(successor), out var cached))
                return cached;
        }

        using var abandon = CancellationTokenSource.CreateLinkedTokenSource(_shutdown.Token);

        // Waited on as in ReadSourceAsync.
        var opening = Task.Run(() => OpenTestedSignerAsync(successor, abandon.Token).AsTask(), CancellationToken.None);
        ISigner signer;
        try
        {
            signer = await opening.WaitAsync(SourceDeadline, _timeProvider, _shutdown.Token).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            // Abandoned: a signer it still produces is disposed, set up before the source is told to stop.
            DisposeIfItOpensLate(opening);
            CancelQuietly(abandon);

            if (_shutdown.IsCancellationRequested)
                throw;

            if (current?.Kid == successor.Kid)
                KeepSigningThroughTheRenewedEntry(current, successor, Describe(ex), ex);
            else
                SetAside(current, successor, Describe(ex), ex);

            return null;
        }

        return TryKeep(successor, signer) ? signer : throw new OperationCanceledException(_shutdown.Token);
    }

    /// <summary>
    /// <paramref name="renewal"/> lists <paramref name="current"/>'s key pair under another source id and failed:
    /// <paramref name="current"/>'s signer signs on, and the next read tries the renewal again.
    /// </summary>
    private void KeepSigningThroughTheRenewedEntry(SigningKey current, SigningKey renewal, string reason, Exception failure)
    {
        _renewalsFailed.Add(SignerId.Of(renewal));
        _logger.LogWarning(
            failure,
            "Key {Kid} is listed again as {SourceKeyId}, but its signer failed ({Failure}); the signer opened " +
            "through {PreviousSourceKeyId} signs on, and the next read tries the renewal again.",
            renewal.Kid, renewal.SourceId.Value, reason, current.SourceId.Value);
    }

    private void LogTakeover(SigningKey? current, SigningKey successor)
    {
        if (current is null)
        {
            _logger.LogInformation(
                "Signing resumes: key {Kid} ({SourceKeyId}) now signs.", successor.Kid, successor.SourceId.Value);
            return;
        }

        _logger.LogInformation(
            "Key {Kid} ({SourceKeyId}) now signs, taking over from {PreviousKid} ({PreviousSourceKeyId}).",
            successor.Kid, successor.SourceId.Value, current.Kid, current.SourceId.Value);
    }

    /// <summary>
    /// Sets <paramref name="successor"/> aside: published but never signing, with the keys around it chosen instead.
    /// Stops signing when no other listed key could sign.
    /// </summary>
    private void SetAside(SigningKey? current, SigningKey successor, string reason, Exception? failure)
    {
        var state = Volatile.Read(ref _state)!;
        _failed.UnionWith(TimelineOf(state)!.SourceIdsOf(successor));
        if (TimelineOf(state)!.SettingAside(successor.Kid) is not { } timeline)
        {
            _logger.LogError(failure, "The signer of key {Kid} ({SourceKeyId}) failed ({Failure}).", successor.Kid, successor.SourceId.Value, reason);
            StopSigning(new ZeeKayDaConfigurationFailure(
                "signing.no_usable_key",
                $"Key '{successor.SourceId.Value}' is due to sign, its signer failed ({reason}), and no other listed key can sign."));
            return;
        }

        Volatile.Write(ref _state, state switch
        {
            Signing signing => signing with { Timeline = timeline },
            _ => (Resuming)state with { Timeline = timeline, KeySet = new SigningKeySet(_algorithm, null, timeline.At(_timeProvider.GetUtcNow()).Published) },
        });
        _logger.LogError(
            failure,
            "Key {Kid} ({SourceKeyId}) is due to sign, but its signer failed ({Failure}); it is set aside until the " +
            "next read, and the rules choose among the keys around it. Fix the key; the next read tries it again.",
            successor.Kid, successor.SourceId.Value, reason);
    }

    private static string Describe(Exception failure) => failure switch
    {
        ZeeKayDaConfigurationException configuration => configuration.AggregatedFailures[0].Code,
        TimeoutException => $"did not complete within {SourceDeadline}",
        _ => failure.GetType().FullName!,
    };

    private static void CancelQuietly(CancellationTokenSource source)
    {
        try
        {
            source.Cancel();
        }
        catch (AggregateException)
        {
            // A callback a source registered on the token threw. Nothing here can act on that, and
            // the caller must still release what it holds.
        }
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

    /// <summary>Keeps a freshly opened signer, or disposes it at once when shutdown has already run.</summary>
    private bool TryKeep(SigningKey key, ISigner signer)
    {
        lock (_gate)
        {
            if (_disposed == 0)
            {
                _signers.Add(SignerId.Of(key), signer);
                return true;
            }
        }

        DisposeQuietly(signer);
        return false;
    }

    /// <summary>Warns about each key dropped now that <paramref name="previous"/> had not already dropped.</summary>
    private void WarnAboutDroppedKeys(SigningKeyTimeline timeline, SigningKeyTimeline? previous)
    {
        var known = previous?.Dropped.Select(drop => drop.Id.Value).ToHashSet(StringComparer.Ordinal) ?? [];
        var fresh = timeline.Dropped.Where(drop => !known.Contains(drop.Id.Value)).ToList();
        foreach (var drop in fresh)
        {
            _logger.LogWarning(
                "Signing key {SourceKeyId} was dropped and is neither published nor used to sign: [{FailureCode}] {Reason}",
                drop.Id.Value, drop.Failure.Code, drop.Failure.Message);
        }

        if (fresh.Count > 0 && timeline.CoverageCutShortTo() is { } usableUntil)
        {
            _logger.LogWarning(
                "With the dropped signing keys gone, the last usable key expires at {UsableUntil}, sooner than the " +
                "listed keys would have. Fix or replace the dropped keys before then.",
                usableUntil);
        }
    }

    /// <summary>Logs each key listed more than once that <paramref name="previous"/> did not already merge the same way.</summary>
    private void LogMergedKeys(SigningKeyTimeline timeline, SigningKeyTimeline? previous)
    {
        var known = previous?.Merged ?? [];
        foreach (var merged in timeline.Merged.Where(merged => !known.Any(old => old.SourceIds.SequenceEqual(merged.SourceIds) && old.Key.SourceId == merged.Key.SourceId)))
        {
            _logger.LogInformation(
                "Signing keys {SourceKeyIds} share one key pair, so they are published as one key, {Kid}; its signer " +
                "opens through {SourceKeyId}, the last of them to expire.",
                string.Join(", ", merged.SourceIds.Select(id => id.Value)),
                merged.Key.Kid,
                merged.Key.SourceId.Value);
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
    /// The wait until the next read or the first change after <paramref name="evaluatedAt"/>, measured against
    /// the clock now, so a change that passed meanwhile fires at once.
    /// </summary>
    private TimeSpan NextWait(SigningKeyTimeline? timeline, DateTimeOffset evaluatedAt)
    {
        var change = timeline?.NextChangeAfter(evaluatedAt) ?? DateTimeOffset.MaxValue;
        var next = change < _nextReadAt ? change : _nextReadAt;
        var remaining = next - _timeProvider.GetUtcNow();
        if (remaining <= TimeSpan.Zero)
            return TimeSpan.Zero;

        // Rounded up: a timer truncates to whole milliseconds, and waking early only re-arms.
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
            // Quietly, so the operator sees the self-test failure rather than a cleanup failure.
            DisposeQuietly(signer);
            throw;
        }

        return signer;
    }

    /// <summary>Disposes a signer on a failure path, swallowing anything but an <see cref="OutOfMemoryException"/>.</summary>
    private static void DisposeQuietly(ISigner signer)
    {
        try
        {
            signer.Dispose();
        }
        catch (Exception ex) when (ex is not OutOfMemoryException)
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
            // Already carries a stable code; kept rather than flattened into signing.signer_unavailable.
            throw;
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            // The type, never ex.Message: a provider message may carry credentials that a public failure
            // message cannot redact. InnerException keeps the root cause.
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

    /// <summary>Bytes that are not a signature of the key's algorithm do not verify; some platforms throw rather than return false.</summary>
    private static bool HasValidSignature(SigningKey key, ReadOnlySpan<byte> signingInput, ReadOnlySpan<byte> signature)
    {
        try
        {
            return SigningAlgorithms.Verify(key.Algorithm, key.PublicKey, signingInput, signature);
        }
        catch (Exception ex) when (ex is CryptographicException or ArgumentException or NotSupportedException)
        {
            _ = ex;
            return false;
        }
    }

    private static SigningKeyTimeline? TimelineOf(SigningKeyRingState state) => state switch
    {
        Signing signing => signing.Timeline,
        Resuming resuming => resuming.Timeline,
        _ => null,
    };

    private static string? ReasonOf(SigningKeyRingState state) => state switch
    {
        Stopped stopped => stopped.Reason,
        Resuming resuming => resuming.Reason,
        _ => null,
    };

    /// <summary>One key pair through one source entry: a renewal under another source id needs its own signer.</summary>
    private readonly record struct SignerId(string Kid, SourceKeyId SourceId)
    {
        internal static SignerId Of(SigningKey key) => new(key.Kid, key.SourceId);
    }
}
