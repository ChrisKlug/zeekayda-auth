namespace ZeeKayDa.Auth.Tokens;

/// <summary>
/// The seam every signing-key provider implements: list the configured keys' public material, and
/// lend a signer for whichever of them the framework chooses to sign with.
/// </summary>
/// <remarks>
/// <para>
/// A source signs under exactly one <see cref="Algorithm"/>, and so does the server: every key it
/// lists is used with that algorithm, and a key whose material does not suit it fails startup.
/// Changing algorithm means a new source and a restart.
/// </para>
/// <para>
/// A source never decides which key signs or which keys are published. The framework decides both
/// from each key's <see cref="SourceKey.NotBefore"/> and <see cref="SourceKey.ExpiresAt"/>: the
/// newest key published for at least the lead time signs, and an older key stays published until no
/// token it signed can still be valid. A source lists every key it has; any of them may be asked to
/// sign.
/// </para>
/// <para>
/// Third parties implement this interface from their own package and register it via
/// <c>builder.AddSigningKeySource&lt;TSource&gt;()</c>.
/// </para>
/// <para>
/// The <see cref="SigningKeyRing"/> constructs and owns the one instance it reads from — nothing
/// registers an <see cref="ISigningKeySource"/> in the container, so no application code can reach
/// it. The ring disposes it once, at shutdown, after the <see cref="ISigner"/> it opened. Implement
/// <see cref="IDisposable"/> if the source holds a handle — a client, a connection — that needs
/// closing; implementing <see cref="IAsyncDisposable"/> without <see cref="IDisposable"/> is rejected
/// at registration time.
/// </para>
/// </remarks>
public interface ISigningKeySource
{
    /// <summary>Gets the algorithm every key this source lists signs under.</summary>
    SigningAlgorithm Algorithm { get; }

    /// <summary>
    /// Lists the configured keys' public material.
    /// </summary>
    /// <param name="cancellationToken">A token to cancel the operation.</param>
    /// <returns>Every key the source holds, in any order.</returns>
    Task<IReadOnlyList<SourceKey>> ReadAsync(CancellationToken cancellationToken = default);

    /// <summary>
    /// Lends a signer for the key identified by <paramref name="id"/>, one of the keys
    /// <see cref="ReadAsync"/> listed.
    /// </summary>
    /// <param name="id">The source's own identifier for the key, as listed by <see cref="ReadAsync"/>.</param>
    /// <param name="cancellationToken">A token to cancel the operation.</param>
    /// <returns>A new signer for the key identified by <paramref name="id"/>.</returns>
    Task<ISigner> CreateSignerAsync(SourceKeyId id, CancellationToken cancellationToken = default);
}
