using System.Collections.Frozen;
using ZeeKayDa.Auth.Clients;
using ZeeKayDa.Auth.Scopes;

namespace ZeeKayDa.Auth.Claims;

/// <summary>
/// The claim types wanted in each destination for one grant: the union of what the granted
/// scopes unlock there, plus the client's additions for it. <see cref="All"/> is what the
/// provider is told to fetch.
/// </summary>
internal sealed record ClaimSelectionPlan(
    IReadOnlySet<string> IdToken,
    IReadOnlySet<string> UserInfo,
    IReadOnlySet<string> AccessToken,
    IReadOnlySet<string> All)
{
    public static ClaimSelectionPlan For(IReadOnlyList<ScopeDefinition> granted, IClientMetadata client)
    {
        ArgumentNullException.ThrowIfNull(granted);
        ArgumentNullException.ThrowIfNull(client);

        var idToken = Wanted(granted.Select(scope => scope.IdTokenClaims), client.AdditionalIdTokenClaims);
        var userInfo = Wanted(granted.Select(scope => scope.UserInfoClaims), client.AdditionalUserInfoClaims);
        var accessToken = Wanted(granted.Select(scope => scope.AccessTokenClaims), client.AdditionalAccessTokenClaims);

        return new ClaimSelectionPlan(
            idToken,
            userInfo,
            accessToken,
            idToken.Concat(userInfo).Concat(accessToken).ToFrozenSet(StringComparer.Ordinal));
    }

    // A null from a custom registration is treated as empty: the registration validator refuses
    // it, and empty withholds rather than grants, so nothing is widened by the fallback.
    private static FrozenSet<string> Wanted(
        IEnumerable<IReadOnlyCollection<string>> unlockedByScopes,
        IReadOnlyCollection<string>? addedByClient) =>
        unlockedByScopes
            .SelectMany(claims => claims ?? [])
            .Concat(addedByClient ?? [])
            .ToFrozenSet(StringComparer.Ordinal);
}
