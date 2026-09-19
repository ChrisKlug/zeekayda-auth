using System.Collections.Frozen;
using ZeeKayDa.Auth.Clients;
using ZeeKayDa.Auth.Scopes;

namespace ZeeKayDa.Auth.Claims;

/// <summary>What a claims resolution is for. The destinations differ in what they want fetched.</summary>
internal enum ClaimsDestination
{
    /// <summary>The tokens the token endpoint issues: the ID token and the access token.</summary>
    Tokens,

    /// <summary>The userinfo endpoint's response.</summary>
    UserInfo,
}

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

    /// <summary>
    /// The plan narrowed to one destination, so the provider is asked for what that destination
    /// will keep and nothing else. Claim values are personal data, and a claim type only the
    /// access token unlocks is I/O a userinfo call has no use for.
    /// </summary>
    public ClaimSelectionPlan For(ClaimsDestination destination) => destination switch
    {
        ClaimsDestination.UserInfo => this with
        {
            IdToken = FrozenSet<string>.Empty,
            AccessToken = FrozenSet<string>.Empty,
            All = UserInfo,
        },
        _ => this,
    };

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
