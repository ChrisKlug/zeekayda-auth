namespace ZeeKayDa.Auth.Tokens;

/// <summary>
/// The immutable state every consumer of the static signing key ring reads: every published key,
/// which one signs, and which algorithms to advertise.
/// </summary>
/// <remarks>
/// Only the framework constructs one, and <see cref="SigningKey"/> is always among
/// <see cref="Published"/>.
/// </remarks>
public sealed class SigningKeySet
{
    internal SigningKeySet(
        SigningKey signingKey, IReadOnlyList<SigningKey> published, IReadOnlyList<SigningAlgorithm> advertisedAlgorithms)
    {
        if (!published.Any(key => string.Equals(key.Kid, signingKey.Kid, StringComparison.Ordinal)))
            throw new ArgumentException("The signing key must be among the published keys.", nameof(published));

        SigningKey = signingKey;
        Published = published;
        AdvertisedAlgorithms = advertisedAlgorithms;
    }

    /// <summary>Gets the key that signs.</summary>
    public SigningKey SigningKey { get; }

    /// <summary>Gets every key to publish, signing key included, oldest first.</summary>
    public IReadOnlyList<SigningKey> Published { get; }

    /// <summary>
    /// Gets the distinct algorithms of <see cref="Published"/>, in ascending order by
    /// <see cref="SigningAlgorithm"/> value — stable across restarts and across replicas with
    /// differently ordered configuration.
    /// </summary>
    /// <remarks>
    /// Derived from the published set, not from <see cref="SigningKey"/> alone, so an algorithm
    /// does not drop out of discovery while tokens signed under it are still live (a retired key's
    /// algorithm remains advertised for as long as that key is published).
    /// </remarks>
    public IReadOnlyList<SigningAlgorithm> AdvertisedAlgorithms { get; }
}
