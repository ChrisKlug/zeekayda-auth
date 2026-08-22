namespace ZeeKayDa.Auth.Tokens;

/// <summary>
/// Optional signing-key-producibility surface for an <see cref="IJwtSigningService"/>
/// implementation. Deliberately a separate interface rather than a member on
/// <see cref="IJwtSigningService"/> itself — adding a member there would be a breaking change for
/// any external, out-of-tree implementation of that interface. A registered
/// <see cref="IJwtSigningService"/> that does not implement this interface simply does not receive
/// the framework-owned advertised-algorithm startup check (see <c>AdvertisedSigningAlgorithmVerifier</c>).
/// </summary>
/// <remarks>
/// <see cref="JwtSigningService{TOptions}"/> implements this interface <b>explicitly</b> and does
/// not mark the implementation <see langword="virtual"/>, so no derived provider can override or
/// weaken it — the same pattern used by <see cref="ISigningStartupSelfTest"/>.
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
/// <param name="ActiveAlgorithm">The algorithm of the currently active signing key.</param>
/// <param name="Algorithms">
/// Every algorithm that could sign a new token now or soon: <see cref="ActiveAlgorithm"/>, plus the
/// algorithm of every key that is not yet active but will become the active signer in due course.
/// Always contains <see cref="ActiveAlgorithm"/>.
/// </param>
public sealed record SigningKeyProducibilitySnapshot(
    SigningAlgorithm ActiveAlgorithm,
    IReadOnlyCollection<SigningAlgorithm> Algorithms);
