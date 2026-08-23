namespace ZeeKayDa.Auth.Tokens;

/// <summary>
/// The seam every signing-key provider implements: report the currently configured keys' public
/// material, and lend a signer for whichever key is reported as <see cref="SourceKeySet.SigningKey"/>.
/// </summary>
/// <remarks>
/// <para>
/// Identical whether a source is read once (<see cref="StaticSigningKeyRing"/>) or polled on a
/// cadence, so a future polling ring can be added without changing a single implementation of this
/// interface.
/// </para>
/// <para>
/// Third parties implement this interface from their own package and register it via
/// <c>AddZeeKayDaSigningKeySource&lt;TSource&gt;()</c> — a public call with no
/// <c>InternalsVisibleTo</c> grant required.
/// </para>
/// </remarks>
public interface ISigningKeySource
{
    /// <summary>
    /// Reads the currently configured keys' public material.
    /// </summary>
    /// <param name="cancellationToken">A token to cancel the operation.</param>
    /// <returns>
    /// The keys currently configured, including which one signs. Build with
    /// <see cref="SourceKeySet.Create"/> from the three named slots, or the
    /// <see cref="SourceKeySet"/> constructor directly.
    /// </returns>
    ValueTask<SourceKeySet> ReadAsync(CancellationToken cancellationToken = default);

    /// <summary>
    /// Lends a signer for the key identified by <paramref name="id"/> — always the source id of the
    /// key most recently reported as <see cref="SourceKeySet.SigningKey"/>.
    /// </summary>
    /// <param name="id">The source's own identifier for the signing key, as reported by
    /// <see cref="ReadAsync"/>.</param>
    /// <param name="cancellationToken">A token to cancel the operation.</param>
    /// <returns>A freshly created, exclusively owned signer for the key identified by
    /// <paramref name="id"/>.</returns>
    ValueTask<ISigner> CreateSignerAsync(SourceKeyId id, CancellationToken cancellationToken = default);
}
