namespace ZeeKayDa.Auth.Tokens;

/// <summary>
/// The seam every signing-key provider implements: list the configured keys' public material, and
/// lend a signer for whichever of them the framework chooses to sign with.
/// </summary>
/// <remarks>
/// <para>
/// A source signs under exactly one <see cref="Algorithm"/>, and so does the server; a listed key whose
/// material does not suit it fails startup. Changing algorithm means a new source and a restart.
/// </para>
/// <para>
/// A source lists every key it has and never decides which signs or which are published: the framework
/// decides from each key's <see cref="SourceKey.NotBefore"/> and <see cref="SourceKey.ExpiresAt"/>.
/// </para>
/// <para>
/// Register an implementation with <c>builder.AddSigningKeySource&lt;TSource&gt;()</c>.
/// </para>
/// <para>
/// The <see cref="SigningKeyRing"/> constructs and owns the one instance, which is not in the container,
/// and disposes it at shutdown after its signers. Implement <see cref="IDisposable"/> if the source holds
/// a handle; <see cref="IAsyncDisposable"/> without <see cref="IDisposable"/> is rejected at registration.
/// </para>
/// </remarks>
public interface ISigningKeySource
{
    /// <summary>Gets the algorithm every key this source lists signs under.</summary>
    SigningAlgorithm Algorithm { get; }

    /// <summary>
    /// Lists the configured keys' public material, and reports each entry that cannot be listed.
    /// </summary>
    /// <param name="cancellationToken">A token to cancel the operation.</param>
    /// <returns>
    /// Every key the source holds, in any order, and a <see cref="SourceKeyFailure"/> for each entry
    /// whose own problem keeps it from being listed.
    /// </returns>
    /// <remarks>
    /// Throw only for a failure that is not about one entry, such as an unreachable vault. A thrown read
    /// changes nothing, so throwing for one entry would hold back every other change, a revocation included.
    /// </remarks>
    Task<SourceKeyListing> ReadAsync(CancellationToken cancellationToken = default);

    /// <summary>
    /// Lends a signer for the key identified by <paramref name="id"/>, one of the keys
    /// <see cref="ReadAsync"/> listed.
    /// </summary>
    /// <param name="id">The source's own identifier for the key, as listed by <see cref="ReadAsync"/>.</param>
    /// <param name="cancellationToken">A token to cancel the operation.</param>
    /// <returns>A new signer for the key identified by <paramref name="id"/>.</returns>
    Task<ISigner> CreateSignerAsync(SourceKeyId id, CancellationToken cancellationToken = default);
}
