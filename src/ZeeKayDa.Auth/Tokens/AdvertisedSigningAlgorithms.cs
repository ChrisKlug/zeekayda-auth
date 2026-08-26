namespace ZeeKayDa.Auth.Tokens;

/// <summary>
/// The single derivation of what <c>id_token_signing_alg_values_supported</c> advertises: the
/// published key set's algorithms, narrowed by the operator's optional filter.
/// </summary>
/// <remarks>
/// Every consumer — the discovery document, the startup check that rejects a filter excluding the
/// signing key's algorithm, and the client registration subset check — resolves through this method,
/// so no caller can derive a different answer from the same inputs.
/// </remarks>
internal static class AdvertisedSigningAlgorithms
{
    /// <summary>
    /// Resolves the algorithms to advertise from <paramref name="keySet"/>, narrowed by
    /// <paramref name="filter"/>.
    /// </summary>
    /// <param name="keySet">The current key set.</param>
    /// <param name="filter">
    /// <see cref="IdTokenOptions.AdvertisedSigningAlgorithms"/>; <see langword="null"/> advertises
    /// the whole published set.
    /// </param>
    /// <returns>
    /// The advertised algorithms, in <see cref="SigningKeySet.AdvertisedAlgorithms"/>' ascending
    /// order — an intersection, so an algorithm the key set cannot produce is unrepresentable here
    /// however the filter is configured.
    /// </returns>
    public static IReadOnlyList<SigningAlgorithm> Resolve(
        SigningKeySet keySet, ICollection<SigningAlgorithm>? filter)
        => filter is null
            ? keySet.AdvertisedAlgorithms
            : [.. keySet.AdvertisedAlgorithms.Where(filter.Contains)];
}
