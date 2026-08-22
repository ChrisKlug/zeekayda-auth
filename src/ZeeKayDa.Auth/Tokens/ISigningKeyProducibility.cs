namespace ZeeKayDa.Auth.Tokens;

/// <summary>
/// Optional signing-key-producibility surface for an <see cref="IJwtSigningService"/>
/// implementation. Deliberately a separate interface rather than a member on
/// <see cref="IJwtSigningService"/> itself — the same interface-segregation call already made for
/// <see cref="ISigningStartupSelfTest"/>: producing a signature and reporting startup-time
/// introspection state are different concerns, and only a startup verifier ever calls this one. A
/// registered <see cref="IJwtSigningService"/> that does not implement this interface simply does
/// not receive the framework-owned advertised-algorithm startup check (see
/// <c>AdvertisedSigningAlgorithmVerifier</c>).
/// </summary>
/// <remarks>
/// Every signing provider shipped in this repository is <see langword="internal sealed"/> and
/// implements this interface via <see cref="JwtSigningService{TOptions}"/>, so in practice none of
/// them override its behaviour — but that is a fact about this repository's own providers, not a
/// language-level guarantee: an explicit, non-virtual interface implementation can still be
/// re-implemented by a derived type.
/// </remarks>
public interface ISigningKeyProducibility
{
    /// <summary>
    /// Returns the algorithm of the currently active signing key, plus every algorithm a key that
    /// will become the active signer soon (not yet active) could sign with. Excludes any key
    /// retained only for its retirement window — such a key can still verify already-issued
    /// tokens, but it never signs a new one.
    /// </summary>
    /// <param name="cancellationToken">A token to cancel the operation.</param>
    ValueTask<SigningKeyProducibilitySnapshot> GetProducibilityAsync(CancellationToken cancellationToken = default);
}

/// <summary>
/// The set of signing algorithms an <see cref="IJwtSigningService"/> can produce a new token with
/// right now or in the near future, as returned by <see cref="ISigningKeyProducibility.GetProducibilityAsync"/>.
/// </summary>
public sealed record SigningKeyProducibilitySnapshot
{
    /// <summary>
    /// Initialises a new snapshot.
    /// </summary>
    /// <param name="activeAlgorithm">The algorithm of the currently active signing key.</param>
    /// <param name="stagedAlgorithms">
    /// The algorithm of every key that is not yet active but will become the active signer in due
    /// course. Must not itself repeat <paramref name="activeAlgorithm"/>-only information — it may
    /// legitimately contain the same algorithm value as <paramref name="activeAlgorithm"/> when a
    /// staged key happens to share it, but it never needs to for <see cref="CanProduce"/> to behave
    /// correctly.
    /// </param>
    /// <exception cref="ArgumentNullException"><paramref name="stagedAlgorithms"/> is <see langword="null"/>.</exception>
    public SigningKeyProducibilitySnapshot(SigningAlgorithm activeAlgorithm, IReadOnlySet<SigningAlgorithm> stagedAlgorithms)
    {
        ArgumentNullException.ThrowIfNull(stagedAlgorithms);

        ActiveAlgorithm = activeAlgorithm;
        StagedAlgorithms = stagedAlgorithms;
    }

    /// <summary>Gets the algorithm of the currently active signing key.</summary>
    public SigningAlgorithm ActiveAlgorithm { get; init; }

    /// <summary>
    /// Gets the algorithm of every key that is not yet active but will become the active signer in
    /// due course. Does not include <see cref="ActiveAlgorithm"/> by construction — use
    /// <see cref="CanProduce"/> to check the full producible set.
    /// </summary>
    public IReadOnlySet<SigningAlgorithm> StagedAlgorithms { get; init; }

    /// <summary>
    /// Returns <see langword="true"/> when <paramref name="algorithm"/> is either
    /// <see cref="ActiveAlgorithm"/> or one of <see cref="StagedAlgorithms"/> — i.e. the provider
    /// can sign a new token with it now or once a staged key activates.
    /// </summary>
    /// <param name="algorithm">The algorithm to check.</param>
    public bool CanProduce(SigningAlgorithm algorithm) =>
        algorithm == ActiveAlgorithm || StagedAlgorithms.Contains(algorithm);
}
