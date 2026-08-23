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

    private SigningKeySet? _current;
    private ISigner? _signer;

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
        _current ?? throw new InvalidOperationException(
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

        var current = Current;
        var signer = _signer ?? throw new InvalidOperationException(
            $"{nameof(StaticSigningKeyRing)} has not completed startup initialization yet.");

        var context = new SigningContext(current.SigningKey);
        var signingInput = buildSigningInput(context, state);

        var signature = await signer.SignAsync(signingInput, cancellationToken).ConfigureAwait(false);

        return new SigningOutcome(signingInput, signature, current.SigningKey);
    }

    /// <inheritdoc/>
    public void Dispose()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0)
            return;

        _signer?.Dispose();
        GC.SuppressFinalize(this);
    }

    async ValueTask ISigningKeyRing.InitializeAsync(CancellationToken cancellationToken)
    {
        var sourceKeys = await _source.ReadAsync(cancellationToken).ConfigureAwait(false);
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
            signer.Dispose();
            throw;
        }

        _signer = signer;
        _current = set;
    }

    SigningKeySet? ISigningKeyRing.CurrentOrNull => _current;

    private async ValueTask<ISigner> OpenSignerAsync(SigningKey signingKey, CancellationToken cancellationToken)
    {
        try
        {
            return await _source.CreateSignerAsync(signingKey.SourceId, cancellationToken).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            throw new ZeeKayDaConfigurationException(
                new ZeeKayDaConfigurationFailure(
                    "signing.signer_unavailable",
                    $"The signer for key '{signingKey.SourceId.Value}' could not be opened: {ex.Message}"),
                ex);
        }
    }
}
