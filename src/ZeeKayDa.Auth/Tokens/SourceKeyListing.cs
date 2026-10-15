using System.Collections.Immutable;

namespace ZeeKayDa.Auth.Tokens;

/// <summary>
/// What one <see cref="ISigningKeySource.ReadAsync"/> found: the keys it could list, and the entries
/// it could not.
/// </summary>
/// <remarks>
/// A failure about one entry is reported here, never thrown, so it cannot hold up the rest: deleting one
/// key while another is broken still unlists it. A failure not about one entry throws from
/// <see cref="ISigningKeySource.ReadAsync"/>, and the framework keeps the keys it last read.
/// </remarks>
public sealed class SourceKeyListing
{
    /// <summary>Initialises a <see cref="SourceKeyListing"/>.</summary>
    /// <param name="keys">Every key the source could list, in any order.</param>
    /// <param name="failures">Every entry the source holds but could not list, each with its own failure.</param>
    public SourceKeyListing(IReadOnlyList<SourceKey> keys, IReadOnlyList<SourceKeyFailure> failures)
    {
        Keys = keys;
        Failures = failures;
    }

    /// <summary>Gets every key the source could list. A copy: the source's own list can change after.</summary>
    public IReadOnlyList<SourceKey> Keys
    {
        get;
        init => field = ImmutableArray.CreateRange(value ?? throw new ArgumentNullException(nameof(Keys)));
    }

    /// <summary>Gets every entry the source could not list, and why. A copy, as <see cref="Keys"/> is.</summary>
    public IReadOnlyList<SourceKeyFailure> Failures
    {
        get;
        init => field = ImmutableArray.CreateRange(value ?? throw new ArgumentNullException(nameof(Failures)));
    }
}
