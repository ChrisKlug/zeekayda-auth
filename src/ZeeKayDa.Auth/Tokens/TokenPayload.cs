using System.Collections.Frozen;

namespace ZeeKayDa.Auth.Tokens;

/// <summary>
/// The claims a token is issued over, already selected and finalized by the caller.
/// </summary>
/// <remarks>
/// <para>
/// Claims are keyed by claim name exactly as they must appear in the token. The issuer performs
/// no selection, renaming, or enrichment — claim selection is the caller's job, done before this
/// type is constructed.
/// </para>
/// <para>
/// Deliberately claims rather than serialized bytes: a JWT issuer serializes them to JSON, but an
/// opaque issuer wants claims to hand to a store, and a payload that arrived pre-serialized would
/// force it to deserialize what the caller just serialized. This is what keeps
/// <see cref="ITokenIssuer"/> implementable with no reference to any JWS-specific type.
/// </para>
/// <para>
/// The constructor snapshots the claims into an immutable copy — the same copy-before-sign
/// discipline the signing ring applies to its input. What was validated is what gets signed:
/// mutating the source dictionary after construction changes nothing, and a source whose
/// enumerator yields a claim name twice is rejected outright rather than serialized as a
/// duplicate JSON member, whose handling RFC 7519 leaves undefined.
/// </para>
/// <para>
/// <strong>Claim values are serialized by their runtime type, whole object graph included.</strong>
/// Use JSON primitives (<see langword="string"/>, numbers, <see langword="bool"/>), arrays of
/// them, or purpose-built claim shapes. Never pass a domain object: every property on it — and on
/// everything it references — lands base64url-encoded inside a token readable by whoever holds it.
/// </para>
/// </remarks>
public sealed record TokenPayload
{
    private readonly IReadOnlyDictionary<string, object?> _claims;

    /// <summary>
    /// Initializes a new instance of the <see cref="TokenPayload"/> class over a snapshot of
    /// <paramref name="Claims"/>.
    /// </summary>
    /// <param name="Claims">The finalized claims. Snapshotted; later mutation has no effect.</param>
    /// <exception cref="ArgumentNullException">
    /// Thrown when <paramref name="Claims"/> is <see langword="null"/>.
    /// </exception>
    /// <exception cref="ArgumentException">
    /// Thrown when <paramref name="Claims"/> yields the same claim name more than once.
    /// </exception>
    public TokenPayload(IReadOnlyDictionary<string, object?> Claims)
    {
        _claims = Snapshot(Claims);
    }

    /// <summary>Gets the claims, as snapshotted at construction.</summary>
    public IReadOnlyDictionary<string, object?> Claims
    {
        get => _claims;
        init => _claims = Snapshot(value);
    }

    /// <summary>Deconstructs this payload into its claims.</summary>
    /// <param name="Claims">The claims, as snapshotted at construction.</param>
    public void Deconstruct(out IReadOnlyDictionary<string, object?> Claims) => Claims = _claims;

    private static FrozenDictionary<string, object?> Snapshot(IReadOnlyDictionary<string, object?> claims)
    {
        ArgumentNullException.ThrowIfNull(claims);

        // TryAdd, not ToFrozenDictionary directly: the latter silently keeps the last occurrence
        // of a duplicate name, which is exactly the ambiguity being rejected.
        var snapshot = new Dictionary<string, object?>(claims.Count, StringComparer.Ordinal);
        foreach (var (name, value) in claims)
        {
            if (!snapshot.TryAdd(name, value))
            {
                throw new ArgumentException(
                    $"Claim '{name}' appears more than once. RFC 7519 leaves duplicate claim " +
                    $"names undefined, so an issuer and a verifier could disagree about the value.",
                    nameof(claims));
            }
        }

        return snapshot.ToFrozenDictionary(StringComparer.Ordinal);
    }
}
