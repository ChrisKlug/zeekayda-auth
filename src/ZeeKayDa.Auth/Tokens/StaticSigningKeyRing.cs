namespace ZeeKayDa.Auth.Tokens;

/// <summary>
/// The shipped <see cref="ISigningKeyRing"/>: reads its <see cref="ISigningKeySource"/> exactly
/// once at startup, builds the key set, opens and self-tests the signer, then never reads again.
/// </summary>
/// <remarks>
/// Owns the one <see cref="ISigner"/> it opens for the process lifetime and disposes it once, at
/// shutdown — a consumer of <see cref="ISigningKeyRing"/> never receives it and never disposes it.
/// A polling implementation can be added behind the same interface later without changing any
/// consumer.
/// </remarks>
public sealed class StaticSigningKeyRing : ISigningKeyRing, IDisposable
{
    private readonly ISigningKeySource _source;
    private readonly TimeProvider _timeProvider;

    // The signing key set and the signer opened for it are read and written together, exactly once,
    // via Interlocked.CompareExchange — never as two independently-updated fields — so a consumer
    // can never observe one without the other, and InitializeAsync can only ever commit once.
    private SignerBinding? _binding;

    // 0 = live, 1 = disposed. int so Interlocked.Exchange makes the transition atomic.
    private int _disposed;

    /// <summary>
    /// Initialises a <see cref="StaticSigningKeyRing"/> over <paramref name="source"/>. Call
    /// <see cref="ISigningKeyRing.InitializeAsync"/> (done automatically at host startup by
    /// <see cref="SigningKeyRingStartupVerifier"/>) before using <see cref="Current"/> or
    /// <see cref="SignAsync{TState}"/>.
    /// </summary>
    /// <param name="source">The signing key source to read once.</param>
    /// <param name="timeProvider">Used to evaluate the signing key's expiry at initialization time.</param>
    /// <exception cref="ArgumentNullException">
    /// Thrown when <paramref name="source"/> or <paramref name="timeProvider"/> is
    /// <see langword="null"/>.
    /// </exception>
    public StaticSigningKeyRing(ISigningKeySource source, TimeProvider timeProvider)
    {
        ArgumentNullException.ThrowIfNull(source);
        ArgumentNullException.ThrowIfNull(timeProvider);

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

        _binding?.Signer.Dispose();
        GC.SuppressFinalize(this);
    }

    async ValueTask ISigningKeyRing.InitializeAsync(CancellationToken cancellationToken)
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

        if (set.SigningKey.ExpiresAt is { } expiresAt && expiresAt <= _timeProvider.GetUtcNow())
        {
            throw new ZeeKayDaConfigurationException(
                new ZeeKayDaConfigurationFailure(
                    "signing.signing_key_expired",
                    $"The Current signing key '{set.SigningKey.Kid}' expired at {expiresAt:O}. An " +
                    "expired signing key issues tokens no relying party will accept."));
        }

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
            // Lost the race: some other call already completed initialization first. Dispose the
            // signer this call opened rather than leaking it — it will never be reachable through
            // Current or SignAsync.
            DisposeQuietly(signer);
            throw new InvalidOperationException(
                $"{nameof(StaticSigningKeyRing)}.InitializeAsync was already called. It must be " +
                "called exactly once.");
        }

        // Dispose() may have run concurrently with the work above, between this instance being
        // constructed and _binding being committed. Re-check now rather than leaving a live signer
        // handle reachable behind a ring that has already reported itself disposed.
        if (Volatile.Read(ref _disposed) != 0)
            signer.Dispose();
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
