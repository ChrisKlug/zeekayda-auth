namespace ZeeKayDa.Auth.Scopes;

/// <summary>
/// Standard OpenID Connect scope definitions: <c>openid</c>, which lists <c>sub</c>, and the four
/// scopes of OpenID Connect Core §5.4, which unlock their claims at the userinfo endpoint.
/// </summary>
/// <remarks>
/// §5.4 returns the <c>profile</c>, <c>email</c>, <c>phone</c> and <c>address</c> claims from the
/// userinfo endpoint when an access token is issued, which in the code flow it always is, so none
/// of those four scopes puts a claim in the ID token by default; <c>openid</c> is the exception and
/// keeps <c>sub</c>, which the framework writes to every token from the grant regardless. A host
/// that wants one of the four scopes' claims in the ID token as well adds them to that scope's
/// <see cref="ScopeDefinition.IdTokenClaims"/>:
/// <c>StandardScopes.Email with { IdTokenClaims = StandardScopes.Email.UserInfoClaims }</c>.
/// A relying party using Microsoft's OpenID Connect handler reads them with
/// <c>options.GetClaimsFromUserInfoEndpoint = true</c>.
/// </remarks>
public static class StandardScopes
{
    private static readonly IReadOnlyCollection<string> OpenIdClaims = Array.AsReadOnly(["sub"]);
    private static readonly IReadOnlyCollection<string> ProfileClaims = Array.AsReadOnly(["name", "family_name", "given_name", "middle_name", "nickname", "preferred_username", "profile", "picture", "website", "gender", "birthdate", "zoneinfo", "locale", "updated_at"]);
    private static readonly IReadOnlyCollection<string> EmailClaims = Array.AsReadOnly(["email", "email_verified"]);
    private static readonly IReadOnlyCollection<string> PhoneClaims = Array.AsReadOnly(["phone_number", "phone_number_verified"]);
    private static readonly IReadOnlyCollection<string> AddressClaims = Array.AsReadOnly(["address"]);

    /// <summary>
    /// Gets the standard <c>openid</c> scope definition. It lists <c>sub</c> for readability;
    /// the framework writes <c>sub</c> from the grant on every token regardless.
    /// </summary>
    public static ScopeDefinition OpenId { get; } = new()
    {
        Name = "openid",
        IsDiscoverable = true,
        IdTokenClaims = OpenIdClaims,
        UserInfoClaims = OpenIdClaims,
    };

    /// <summary>
    /// Gets the standard <c>profile</c> scope definition.
    /// </summary>
    public static ScopeDefinition Profile { get; } = new()
    {
        Name = "profile",
        IsDiscoverable = true,
        UserInfoClaims = ProfileClaims,
    };

    /// <summary>
    /// Gets the standard <c>email</c> scope definition.
    /// </summary>
    public static ScopeDefinition Email { get; } = new()
    {
        Name = "email",
        IsDiscoverable = true,
        UserInfoClaims = EmailClaims,
    };

    /// <summary>
    /// Gets the standard <c>phone</c> scope definition.
    /// </summary>
    public static ScopeDefinition Phone { get; } = new()
    {
        Name = "phone",
        IsDiscoverable = true,
        UserInfoClaims = PhoneClaims,
    };

    /// <summary>
    /// Gets the standard <c>address</c> scope definition.
    /// </summary>
    public static ScopeDefinition Address { get; } = new()
    {
        Name = "address",
        IsDiscoverable = true,
        UserInfoClaims = AddressClaims,
    };

    /// <summary>
    /// Gets all standard OpenID Connect scope definitions.
    /// </summary>
    public static IReadOnlyCollection<ScopeDefinition> All { get; } = Array.AsReadOnly([OpenId, Profile, Email, Phone, Address]);
}
