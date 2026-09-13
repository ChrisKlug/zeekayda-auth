using System.Collections.Frozen;

namespace ZeeKayDa.Auth.Claims;

/// <summary>
/// What an <see cref="IClaimsProvider"/> is handed: the subject, the scopes the grant carries,
/// the claim types selection will keep, and the grant family.
/// </summary>
/// <param name="Sub">The subject identifier the tokens are for.</param>
/// <param name="Scopes">
/// The granted scopes, in order. A custom scope's meaning to the host is the provider's to
/// interpret; the standard scopes are already expressed by <paramref name="ClaimTypes"/>.
/// </param>
/// <param name="ClaimTypes">
/// Every claim type that selection will keep for this grant, across the ID token, the access
/// token and userinfo, the client's own additions included. A hint for what to fetch, not a
/// filter: a record of a type not listed here is dropped, and a listed type the provider does
/// not return is omitted from the token.
/// </param>
/// <param name="FamilyId">
/// The refresh-token family of the grant, stable across every rotation of it, or
/// <see langword="null"/> at userinfo, where there is no grant. Together with
/// <paramref name="Sub"/> it is the natural cache key for a provider that wants to spare its
/// identity store on rotation.
/// </param>
/// <remarks>
/// The client that asked is deliberately absent. Claims resolution is a subject-level concern;
/// the only client-dependent step is selection, which runs after the provider returns and can
/// only widen what is kept. The collections are snapshotted at construction into read-only
/// copies the context owns, so a provider holds no reference to the grant's own scope list and
/// nothing it does to what it was handed can reach a token.
/// </remarks>
/// <exception cref="ArgumentException">Thrown when <paramref name="Sub"/> is <see langword="null"/> or empty.</exception>
/// <exception cref="ArgumentNullException">Thrown when <paramref name="Scopes"/> or <paramref name="ClaimTypes"/> is <see langword="null"/>.</exception>
public sealed record ClaimsProviderContext(
    string Sub,
    IReadOnlyList<string> Scopes,
    IReadOnlySet<string> ClaimTypes,
    string? FamilyId)
{
    /// <inheritdoc cref="ClaimsProviderContext"/>
    public string Sub { get; init; } = !string.IsNullOrEmpty(Sub)
        ? Sub
        : throw new ArgumentException("The subject identifier must not be null or empty.", nameof(Sub));

    /// <inheritdoc cref="ClaimsProviderContext"/>
    public IReadOnlyList<string> Scopes { get; init; } = Snapshot(Scopes ?? throw new ArgumentNullException(nameof(Scopes)));

    /// <inheritdoc cref="ClaimsProviderContext"/>
    public IReadOnlySet<string> ClaimTypes { get; init; } = Snapshot(ClaimTypes ?? throw new ArgumentNullException(nameof(ClaimTypes)));

    /// <summary>Names the scopes and counts the claim types; never prints the subject.</summary>
    public override string ToString() =>
        $"ClaimsProviderContext {{ Scopes = [{string.Join(' ', Scopes)}], ClaimTypes = {ClaimTypes.Count}, FamilyId = {(FamilyId is null ? "none" : "present")} }}";

    // A copy the context owns: the grant's list stays the endpoint's, and what the provider is
    // handed cannot be downcast to a writable collection.
    private static IReadOnlyList<string> Snapshot(IReadOnlyList<string> scopes) =>
        Array.AsReadOnly(scopes.ToArray());

    private static IReadOnlySet<string> Snapshot(IReadOnlySet<string> claimTypes) =>
        claimTypes.ToFrozenSet(StringComparer.Ordinal);
}
