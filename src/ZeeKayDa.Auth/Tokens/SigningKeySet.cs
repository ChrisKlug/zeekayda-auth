namespace ZeeKayDa.Auth.Tokens;

/// <summary>
/// The immutable state every consumer of the static signing key ring reads: every published key,
/// which one signs, and the one algorithm they all sign under.
/// </summary>
/// <remarks>
/// Only the framework constructs one, <see cref="SigningKey"/> is always among
/// <see cref="Published"/>, and every published key has <see cref="Algorithm"/>.
/// </remarks>
public sealed class SigningKeySet
{
    internal SigningKeySet(SigningKey signingKey, IReadOnlyList<SigningKey> published)
    {
        if (!published.Any(key => string.Equals(key.Kid, signingKey.Kid, StringComparison.Ordinal)))
            throw new ArgumentException("The signing key must be among the published keys.", nameof(published));

        if (published.Any(key => key.Algorithm != signingKey.Algorithm))
            throw new ArgumentException("Every published key must share the signing key's algorithm.", nameof(published));

        SigningKey = signingKey;
        Published = published;
    }

    /// <summary>Gets the key that signs.</summary>
    public SigningKey SigningKey { get; }

    /// <summary>Gets every key to publish, signing key included, oldest first.</summary>
    public IReadOnlyList<SigningKey> Published { get; }

    /// <summary>
    /// Gets the algorithm every published key signs under — the source's
    /// <see cref="ISigningKeySource.Algorithm"/>, and the one value of
    /// <c>id_token_signing_alg_values_supported</c>.
    /// </summary>
    public SigningAlgorithm Algorithm => SigningKey.Algorithm;
}
