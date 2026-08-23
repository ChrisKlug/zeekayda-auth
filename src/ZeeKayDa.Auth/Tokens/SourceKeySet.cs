using System.Collections.Immutable;

namespace ZeeKayDa.Auth.Tokens;

/// <summary>
/// The keys an <see cref="ISigningKeySource"/> reports on one read: which key signs, and which
/// other keys (if any) are published alongside it.
/// </summary>
/// <remarks>
/// The signing key is a distinct, non-nullable constructor parameter rather than a positional
/// index into <see cref="Keys"/>, so "which key signs" can never be expressed ambiguously — the
/// three-slot phases of a rotation ("stage B" publishes <c>Current</c> and <c>Next</c>; "cut over"
/// publishes <c>Previous</c> and <c>Current</c>) differ only in which key is passed as the signer,
/// never in argument position.
/// </remarks>
public sealed class SourceKeySet
{
    /// <summary>
    /// Initialises a <see cref="SourceKeySet"/> from an explicit signing key and any number of
    /// additional keys to publish alongside it.
    /// </summary>
    /// <param name="signingKey">The key that signs.</param>
    /// <param name="alsoPublished">Additional keys to publish, but never sign with.</param>
    /// <exception cref="ArgumentNullException">
    /// Thrown when <paramref name="signingKey"/> or <paramref name="alsoPublished"/> is
    /// <see langword="null"/>.
    /// </exception>
    /// <exception cref="ZeeKayDaConfigurationException">
    /// Thrown with failure code <c>signing.null_published_key</c> when <paramref name="alsoPublished"/>
    /// contains a <see langword="null"/> element.
    /// </exception>
    public SourceKeySet(SourceKey signingKey, params SourceKey[] alsoPublished)
    {
        ArgumentNullException.ThrowIfNull(signingKey);
        ArgumentNullException.ThrowIfNull(alsoPublished);

        if (Array.IndexOf(alsoPublished, null) >= 0)
        {
            throw new ZeeKayDaConfigurationException(
                new ZeeKayDaConfigurationFailure(
                    "signing.null_published_key",
                    "The signing key source reported a null key among the keys published alongside " +
                    "the signing key. Every element of alsoPublished must be non-null."));
        }

        SigningKey = signingKey;
        Keys = ImmutableArray.Create(signingKey).AddRange(alsoPublished);
    }

    /// <summary>
    /// Builds a <see cref="SourceKeySet"/> from the three named slots the framework's rotation
    /// model uses: <paramref name="current"/> signs, <paramref name="previous"/> and
    /// <paramref name="next"/> are published only. Either or both may be omitted.
    /// </summary>
    /// <param name="previous">The previously active key, still published so relying parties can
    /// verify tokens it signed; or <see langword="null"/> if there is none.</param>
    /// <param name="current">The key that signs. Required.</param>
    /// <param name="next">A key staged to become active later, published in advance; or
    /// <see langword="null"/> if there is none.</param>
    /// <returns>A <see cref="SourceKeySet"/> whose signing key is <paramref name="current"/>.</returns>
    /// <exception cref="ZeeKayDaConfigurationException">
    /// Thrown with failure code <c>signing.no_current_key</c> when <paramref name="current"/> is
    /// <see langword="null"/>.
    /// </exception>
    public static SourceKeySet Create(SourceKey? previous, SourceKey? current, SourceKey? next)
    {
        if (current is null)
        {
            throw new ZeeKayDaConfigurationException(
                new ZeeKayDaConfigurationFailure(
                    "signing.no_current_key",
                    "No Current signing key is configured. The Current slot is required — Previous " +
                    "and Next are optional."));
        }

        var alsoPublished = new List<SourceKey>(2);
        if (previous is not null)
            alsoPublished.Add(previous);
        if (next is not null)
            alsoPublished.Add(next);

        return new SourceKeySet(current, [.. alsoPublished]);
    }

    /// <summary>Gets the key that signs.</summary>
    public SourceKey SigningKey { get; }

    /// <summary>
    /// Gets every key reported by this read, signing key first, then the keys passed as
    /// <c>alsoPublished</c> in the order supplied.
    /// </summary>
    public IReadOnlyList<SourceKey> Keys { get; }
}
