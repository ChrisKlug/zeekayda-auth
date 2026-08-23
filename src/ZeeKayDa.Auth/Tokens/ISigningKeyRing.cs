namespace ZeeKayDa.Auth.Tokens;

/// <summary>
/// What every signing consumer depends on: the current <see cref="SigningKeySet"/>, and the ability
/// to sign with the key currently designated as the signer.
/// </summary>
/// <remarks>
/// <para>
/// <strong>Framework-sealed.</strong> <see cref="InitializeAsync"/> and <see cref="CurrentOrNull"/>
/// are <see langword="internal"/>, so only assemblies named in this project's
/// <c>InternalsVisibleTo</c> declarations can implement this interface — the shipped
/// <see cref="StaticSigningKeyRing"/> today, a future polling ring later. A third party extends
/// signing by implementing <see cref="ISigningKeySource"/> instead; bypassing
/// <see cref="InitializeAsync"/>'s startup self-test is not an extension point.
/// </para>
/// <para>
/// <see cref="SignAsync{TState}"/>'s callback is synchronous by design: the caller cannot perform
/// I/O while the key is resolved, and the returned <see cref="SigningOutcome"/> makes header/key
/// disagreement unrepresentable rather than merely detected.
/// </para>
/// </remarks>
public interface ISigningKeyRing
{
    /// <summary>
    /// Gets the currently active key set.
    /// </summary>
    /// <exception cref="InvalidOperationException">
    /// Thrown when the ring has not yet completed startup initialization.
    /// </exception>
    SigningKeySet Current { get; }

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
    ValueTask<SigningOutcome> SignAsync<TState>(
        TState state,
        Func<SigningContext, TState, ReadOnlyMemory<byte>> buildSigningInput,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Reads the source, builds the key set, opens the signer, and self-tests it. Called exactly
    /// once by <see cref="SigningKeyRingStartupVerifier"/> at host startup.
    /// </summary>
    /// <param name="cancellationToken">A token that is signalled if the host is shutting down.</param>
    internal ValueTask InitializeAsync(CancellationToken cancellationToken);

    /// <summary>
    /// Gets the currently active key set, or <see langword="null"/> when the ring has not yet
    /// completed startup initialization — lets a health check report "not initialized" rather than
    /// throwing.
    /// </summary>
    internal SigningKeySet? CurrentOrNull { get; }
}
