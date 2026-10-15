using ZeeKayDa.Auth.Scopes;

namespace ZeeKayDa.Auth.Clients;

/// <summary>
/// Refuses a client addition naming a claim any scope unlocks in any destination, so every consent-bearing
/// claim stays behind a scope the user can decline.
/// </summary>
/// <remarks>
/// Across every destination, since no scope lists <c>email</c> for the access token, and ignoring case, as a
/// <c>ClaimsPrincipal</c> does. Runs at selection: the registration validator cannot see the scopes.
/// </remarks>
internal static class ClientClaimAdditions
{
    /// <summary>The first addition a scope also unlocks, or <see langword="null"/> when there is none.</summary>
    public static ClaimAdditionCollision? FindCollision(IClient client, IEnumerable<ScopeDefinition> scopes)
    {
        ArgumentNullException.ThrowIfNull(client);
        ArgumentNullException.ThrowIfNull(scopes);

        if (HasNoAdditions(client))
            return null;

        var unlocked = UnlockedByAnyScope(scopes);

        return Collision(unlocked, client.AdditionalIdTokenClaims, nameof(IClient.AdditionalIdTokenClaims))
            ?? Collision(unlocked, client.AdditionalUserInfoClaims, nameof(IClient.AdditionalUserInfoClaims))
            ?? Collision(unlocked, client.AdditionalAccessTokenClaims, nameof(IClient.AdditionalAccessTokenClaims));
    }

    private static bool HasNoAdditions(IClient client) =>
        IsEmpty(client.AdditionalIdTokenClaims)
        && IsEmpty(client.AdditionalUserInfoClaims)
        && IsEmpty(client.AdditionalAccessTokenClaims);

    private static bool IsEmpty(IReadOnlyCollection<string>? additions) => additions is null or { Count: 0 };

    /// <summary>Every claim any scope unlocks, mapped to the first scope unlocking it; the catalog has refused null lists already.</summary>
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
