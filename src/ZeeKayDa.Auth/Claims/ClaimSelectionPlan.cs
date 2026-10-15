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
/// The claim types each destination wants for one grant: what the granted scopes unlock there, plus the
/// client's additions. <see cref="All"/> is what the provider is asked to fetch.
/// </summary>
internal sealed record ClaimSelectionPlan(
    IReadOnlySet<string> IdToken,
    IReadOnlySet<string> UserInfo,
    IReadOnlySet<string> AccessToken,
    IReadOnlySet<string> All)
{
    public static ClaimSelectionPlan For(IReadOnlyList<ScopeDefinition> granted, IClient client)
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
    /// The plan narrowed to one destination, so the provider fetches no personal data that destination will
    /// not keep, and a claim only another destination wants cannot fail this one.
    /// </summary>
    public ClaimSelectionPlan For(ClaimsDestination destination) => destination switch
    {
        ClaimsDestination.UserInfo => this with
        {
            IdToken = FrozenSet<string>.Empty,
            AccessToken = FrozenSet<string>.Empty,
            All = UserInfo,
        },
        ClaimsDestination.Tokens => this with
        {
            UserInfo = FrozenSet<string>.Empty,
            All = IdToken.Concat(AccessToken).ToFrozenSet(StringComparer.Ordinal),
        },
        _ => this,
    };

    // Scope lists are never null past the catalog; a null client addition reads as empty, which
    // withholds rather than grants.
    private static FrozenSet<string> Wanted(
        IEnumerable<IReadOnlyCollection<string>> unlockedByScopes,
        IReadOnlyCollection<string>? addedByClient) =>
        unlockedByScopes
            .SelectMany(claims => claims)
            .Concat(addedByClient ?? [])
            .ToFrozenSet(StringComparer.Ordinal);
}
