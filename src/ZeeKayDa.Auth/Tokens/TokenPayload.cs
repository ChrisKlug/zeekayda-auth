using System.Collections.Frozen;

namespace ZeeKayDa.Auth.Tokens;

/// <summary>
/// The claims a token is issued over, already selected and finalized by the caller.
/// </summary>
/// <remarks>
/// <para>
/// Claims are keyed by name exactly as they appear in the token; the issuer selects, renames and adds
/// nothing. They are claims rather than bytes so an opaque issuer can store them without deserializing.
/// </para>
/// <para>
/// The constructor snapshots the claims, so later mutation changes nothing, and refuses a name yielded
/// twice, since RFC 7519 leaves duplicate members undefined.
/// </para>
/// <para>
/// <strong>Claim values are serialized by their runtime type, whole object graph included.</strong>
/// Use JSON primitives, arrays of them, or purpose-built claim shapes, never a domain object: every
/// property it reaches lands in a token readable by whoever holds it. Framework-selected claims arrive as
/// <see cref="Claims.ClaimValue"/>, which <c>System.Text.Json</c> writes as the JSON it holds; another
/// serializer reads <see cref="Claims.ClaimValue.Kind"/> and writes with <see cref="Claims.ClaimValue.WriteTo"/>.
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
