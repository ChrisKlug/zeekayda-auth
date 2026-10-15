using System.Collections.Frozen;

namespace ZeeKayDa.Auth.Claims;

/// <summary>
/// What an <see cref="IClaimsProvider"/> is handed: the subject, the scopes the grant carries,
/// the claim types selection will keep, and the grant family.
/// </summary>
/// <param name="Sub">The subject identifier the tokens are for.</param>
/// <param name="Scopes">
/// The granted scopes, in order; the standard ones are already expressed by <paramref name="ClaimTypes"/>.
/// </param>
/// <param name="ClaimTypes">
/// The claim types selection will keep for this operation, client additions included: the ID and
/// access tokens' at a token exchange, the userinfo types at userinfo. A fetch hint, never a disclosure
/// plan, since the other operation may release more to the same grant.
/// </param>
/// <param name="FamilyId">
/// The grant's refresh-token family, stable across rotations, or <see langword="null"/> at userinfo;
/// with <paramref name="Sub"/>, the natural cache key.
/// </param>
/// <remarks>
/// The client is deliberately absent: resolution is per subject, and selection afterwards is the only
/// client-dependent step. The collections are read-only copies, so nothing a provider does reaches a token.
/// </remarks>
/// <exception cref="ArgumentException">Thrown when <paramref name="Sub"/> is <see langword="null"/> or empty.</exception>
/// <exception cref="ArgumentNullException">Thrown when <paramref name="Scopes"/> or <paramref name="ClaimTypes"/> is <see langword="null"/>.</exception>
public sealed record ClaimsProviderContext(
    string Sub,
    IReadOnlyList<string> Scopes,
    IReadOnlySet<string> ClaimTypes,
    string? FamilyId)
{
    /// <summary><inheritdoc cref="ClaimsProviderContext" path="/param[@name='Sub']/node()"/></summary>
    public string Sub { get; } = !string.IsNullOrEmpty(Sub)
        ? Sub
        : throw new ArgumentException("The subject identifier must not be null or empty.", nameof(Sub));

    /// <summary><inheritdoc cref="ClaimsProviderContext" path="/param[@name='Scopes']/node()"/></summary>
    public IReadOnlyList<string> Scopes { get; } = Snapshot(Scopes ?? throw new ArgumentNullException(nameof(Scopes)));

    /// <summary><inheritdoc cref="ClaimsProviderContext" path="/param[@name='ClaimTypes']/node()"/></summary>
    public IReadOnlySet<string> ClaimTypes { get; } = Snapshot(ClaimTypes ?? throw new ArgumentNullException(nameof(ClaimTypes)));

    /// <summary>Names the scopes and counts the claim types; never prints the subject.</summary>
    public override string ToString() =>
        $"ClaimsProviderContext {{ Scopes = [{string.Join(' ', Scopes)}], ClaimTypes = {ClaimTypes.Count}, FamilyId = {(FamilyId is null ? "none" : "present")} }}";

    // A copy the context owns, which cannot be downcast to a writable collection.
    private static IReadOnlyList<string> Snapshot(IReadOnlyList<string> scopes) =>
        Array.AsReadOnly(scopes.ToArray());

    private static IReadOnlySet<string> Snapshot(IReadOnlySet<string> claimTypes) =>
        claimTypes.ToFrozenSet(StringComparer.Ordinal);
}
