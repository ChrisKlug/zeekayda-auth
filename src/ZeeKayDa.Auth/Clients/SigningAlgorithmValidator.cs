using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.Clients;

/// <summary>
/// Validates a client's <see cref="IClientMetadata.AllowedSigningAlgorithms"/> against the
/// algorithms the server advertises and records a <see cref="ZeeKayDaConfigurationFailure"/> for
/// every rule it breaks.
/// </summary>
internal static class SigningAlgorithmValidator
{
    /// <summary>
    /// Validates the client's allowed signing algorithms.
    /// </summary>
    /// <param name="client">The client registration.</param>
    /// <param name="keyRing">The signing key ring, or <see langword="null"/> when none is registered.</param>
    /// <param name="advertisedFilter">The operator's <c>IdToken.AdvertisedSigningAlgorithms</c> filter.</param>
    /// <param name="failures">The failures to append to.</param>
    /// <returns>
    /// <see langword="false"/> when the client declares algorithms but there is nothing to check
    /// them against yet; otherwise <see langword="true"/>.
    /// </returns>
    internal static bool Validate(
        IClientRegistration client,
        ISigningKeyRing? keyRing,
        ICollection<SigningAlgorithm>? advertisedFilter,
        List<ZeeKayDaConfigurationFailure> failures)
    {
        var algorithms = client.AllowedSigningAlgorithms;

        if (algorithms is null)
            return true;

        if (algorithms.Count == 0)
        {
            failures.Add(new ZeeKayDaConfigurationFailure(
                "client.signing_algorithms.empty_when_set",
                $"Client '{client.ClientId}' has AllowedSigningAlgorithms set to a non-null empty set. " +
                "When set, AllowedSigningAlgorithms must contain at least one value, or be null to inherit the server default."));
            return true;
        }

        // Nothing to be a subset of: no ring has read its source yet (a repository validating
        // from its own constructor, before startup verification runs) and the operator has
        // stated no ceiling either. The JWT issuer enforces the set again at signing time, so
        // a mismatch still fails closed there; this window is only the earlier, clearer
        // message, and the caller says so rather than passing silently.
        if (ResolveServerAlgorithms(keyRing, advertisedFilter) is not { } serverAlgorithms)
            return false;

        // The key that signs today must be in the set, not only a key that is merely published:
        // with a ring that reads its source once, a client pinned to a next or previous key's
        // algorithm would otherwise pass startup and be refused on every exchange.
        if (keyRing?.CurrentOrNull is { } keySet && !algorithms.Contains(keySet.SigningKey.Algorithm))
        {
            failures.Add(new ZeeKayDaConfigurationFailure(
                "client.signing_algorithms.excludes_signing_key",
                $"Client '{client.ClientId}' has AllowedSigningAlgorithms that exclude '{keySet.SigningKey.Algorithm}', " +
                "the algorithm of the current signing key, so no ID token could be issued to it. Add that " +
                "algorithm, or sign with a key the client allows."));
        }

        foreach (var algorithm in algorithms.Where(algorithm => !serverAlgorithms.Contains(algorithm)))
        {
            failures.Add(new ZeeKayDaConfigurationFailure(
                "client.signing_algorithms.not_subset",
                $"Client '{client.ClientId}' has AllowedSigningAlgorithms entry '{algorithm}' that the " +
                $"server does not advertise. Advertised: [{string.Join(", ", serverAlgorithms)}]. The " +
                "advertised set is the configured signing keys' algorithms, narrowed by " +
                "IdToken.AdvertisedSigningAlgorithms when that filter is set — add a key for " +
                $"'{algorithm}', or remove it from this client."));
        }

        return true;
    }

    /// <summary>
    /// The algorithms a client's <c>AllowedSigningAlgorithms</c> must be a subset of: the advertised
    /// set once the ring has read its source, the operator's filter alone before that, and
    /// <see langword="null"/> when neither exists.
    /// </summary>
    private static IReadOnlyCollection<SigningAlgorithm>? ResolveServerAlgorithms(
        ISigningKeyRing? keyRing,
        ICollection<SigningAlgorithm>? advertisedFilter)
    {
        // CurrentOrNull rather than Current: this validator runs from repository constructors, which
        // a custom repository may drive before the ring has been initialized. Throwing there would
        // turn "the check cannot run yet" into a startup crash.
        return keyRing?.CurrentOrNull is { } keySet
            ? AdvertisedSigningAlgorithms.Resolve(keySet, advertisedFilter)
            : advertisedFilter?.ToArray();
    }
}
