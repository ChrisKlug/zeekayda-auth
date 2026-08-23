namespace ZeeKayDa.Auth.Tokens;

/// <summary>
/// The immutable state every consumer of the static signing key ring reads: every published key,
/// which one signs, and which algorithms to advertise.
/// </summary>
/// <remarks>
/// The only way to obtain an instance is <see cref="SigningKeySetBuilder.Build"/>, and its
/// constructor is <see langword="internal"/>.
/// </remarks>
public sealed class SigningKeySet
{
    internal SigningKeySet(
        SigningKey signingKey, IReadOnlyList<SigningKey> published, IReadOnlyList<SigningAlgorithm> advertisedAlgorithms)
    {
        SigningKey = signingKey;
        Published = published;
        AdvertisedAlgorithms = advertisedAlgorithms;
    }

    /// <summary>Gets the key that signs.</summary>
    public SigningKey SigningKey { get; }

    /// <summary>Gets every key to publish, signing key included.</summary>
    public IReadOnlyList<SigningKey> Published { get; }

    /// <summary>
    /// Gets the distinct algorithms of <see cref="Published"/>, in ascending order by
    /// <see cref="SigningAlgorithm"/> value — stable across restarts and across replicas with
    /// differently ordered configuration.
    /// </summary>
    /// <remarks>
    /// Derived from the published set, not from <see cref="SigningKey"/> alone, so an algorithm
    /// does not drop out of discovery while tokens signed under it are still live (a <c>Previous</c>
    /// key's algorithm remains advertised for as long as that key is published).
    /// </remarks>
    public IReadOnlyList<SigningAlgorithm> AdvertisedAlgorithms { get; }
}
