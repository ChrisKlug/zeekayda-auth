namespace ZeeKayDa.Auth.Tokens;

/// <summary>
/// The immutable state every consumer of the signing key ring reads: every published key, which one
/// signs, and the one algorithm they all sign under.
/// </summary>
/// <remarks>
/// Only the framework constructs one. When <see cref="SigningKey"/> is set it is among
/// <see cref="Published"/>, and every published key has <see cref="Algorithm"/>.
/// </remarks>
public sealed class SigningKeySet
{
    internal SigningKeySet(SigningAlgorithm algorithm, SigningKey? signingKey, IReadOnlyList<SigningKey> published)
    {
        if (signingKey is not null && !published.Any(key => string.Equals(key.Kid, signingKey.Kid, StringComparison.Ordinal)))
            throw new ArgumentException("The signing key must be among the published keys.", nameof(published));

        if (published.Any(key => key.Algorithm != algorithm))
            throw new ArgumentException("Every published key must sign under the set's algorithm.", nameof(published));

        Algorithm = algorithm;
        SigningKey = signingKey;
        Published = published;
    }

    /// <summary>
    /// Gets the key that signs, or <see langword="null"/> when nothing signs: the source listed no keys
    /// or a list the ring must refuse, or — transiently — the ring is handing signing over to a listed
    /// key after a stop or after the signing key left the list.
    /// </summary>
    public SigningKey? SigningKey { get; }

    /// <summary>
    /// Gets every key to publish, signing key included, oldest first. Empty when signing has stopped;
    /// during a handover after a stop, the listed keys due to be published.
    /// </summary>
    public IReadOnlyList<SigningKey> Published { get; }

    /// <summary>
    /// Gets the algorithm every published key signs under — the source's
    /// <see cref="ISigningKeySource.Algorithm"/>, read once at startup, and the one value of
    /// <c>id_token_signing_alg_values_supported</c>.
    /// </summary>
    public SigningAlgorithm Algorithm { get; }

    /// <summary>The set served while signing has stopped: no signing key, nothing published.</summary>
    internal static SigningKeySet Stopped(SigningAlgorithm algorithm) => new(algorithm, null, []);
}
