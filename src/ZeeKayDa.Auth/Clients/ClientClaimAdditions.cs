using ZeeKayDa.Auth.Scopes;

namespace ZeeKayDa.Auth.Clients;

/// <summary>
/// The guard on a client's <c>Additional…Claims</c>: an addition may not name a claim that any
/// registered scope unlocks in any destination. The consent page lists scopes, so an addition is
/// operator policy the user never sees; the guard keeps every consent-bearing claim behind the
/// scope the user can decline.
/// </summary>
/// <remarks>
/// Checked across every destination on purpose. A per-destination check would let
/// <c>AdditionalAccessTokenClaims = ["email"]</c> through, since no scope lists <c>email</c> for
/// the access token, and an API would then read a claim the user never consented to. Compared
/// ignoring case, because a consuming <c>ClaimsPrincipal</c> does: an addition of <c>Email</c>
/// would otherwise deliver what a client's <c>FindFirst("email")</c> reads. Runs on every lookup
/// that selects claims rather than once at registration: the registration validator's verdict is
/// memoised by fingerprint and cannot see the scope repository, so a scope added later would
/// leave a stale "valid".
/// </remarks>
internal static class ClientClaimAdditions
{
    /// <summary>The first addition a scope also unlocks, or <see langword="null"/> when there is none.</summary>
    public static ClaimAdditionCollision? FindCollision(IClientMetadata client, IEnumerable<ScopeDefinition> scopes)
    {
        ArgumentNullException.ThrowIfNull(client);
        ArgumentNullException.ThrowIfNull(scopes);

        // The common client adds nothing, and building the map is the whole cost of the check.
        if (HasNoAdditions(client))
            return null;

        var unlocked = UnlockedByAnyScope(scopes);

        return Collision(unlocked, client.AdditionalIdTokenClaims, nameof(IClientMetadata.AdditionalIdTokenClaims))
            ?? Collision(unlocked, client.AdditionalUserInfoClaims, nameof(IClientMetadata.AdditionalUserInfoClaims))
            ?? Collision(unlocked, client.AdditionalAccessTokenClaims, nameof(IClientMetadata.AdditionalAccessTokenClaims));
    }

    private static bool HasNoAdditions(IClientMetadata client) =>
        IsEmpty(client.AdditionalIdTokenClaims)
        && IsEmpty(client.AdditionalUserInfoClaims)
        && IsEmpty(client.AdditionalAccessTokenClaims);

    private static bool IsEmpty(IReadOnlyCollection<string>? additions) => additions is null or { Count: 0 };

    /// <summary>
    /// Every claim any scope unlocks anywhere, each mapped to the first scope that unlocks it.
    /// </summary>
    /// <remarks>
    /// No null guard on the lists: every definition reaching here came through
    /// <c>ValidatedScopeCatalog</c>, which refuses a repository serving a null list or a blank
    /// claim name.
    /// </remarks>
    private static Dictionary<string, string> UnlockedByAnyScope(IEnumerable<ScopeDefinition> scopes)
    {
        var unlocked = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var scope in scopes)
        {
            var claims = scope.IdTokenClaims.Concat(scope.UserInfoClaims).Concat(scope.AccessTokenClaims);
            foreach (var claim in claims)
                unlocked.TryAdd(claim, scope.Name);
        }

        return unlocked;
    }

    private static ClaimAdditionCollision? Collision(
        Dictionary<string, string> unlocked,
        IReadOnlyCollection<string>? additions,
        string property)
    {
        foreach (var claim in additions ?? [])
        {
            if (claim is not null && unlocked.TryGetValue(claim, out var scope))
                return new ClaimAdditionCollision(claim, scope, property);
        }

        return null;
    }
}

/// <summary>An addition that names a claim a scope unlocks: the claim, the scope, and the property it was added on.</summary>
internal readonly record struct ClaimAdditionCollision(string Claim, string Scope, string Property)
{
    public string Describe(string clientId) =>
        $"Client '{clientId}' names '{Claim}' in {Property}, but the '{Scope}' scope unlocks that claim. A claim " +
        "a scope unlocks can only be granted through that scope, so the user can consent to it; remove it from the " +
        $"client's additions. To change which tokens the '{Scope}' scope releases it in, set that scope's " +
        "IdTokenClaims, UserInfoClaims or AccessTokenClaims.";
}
