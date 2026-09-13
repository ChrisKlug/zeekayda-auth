namespace ZeeKayDa.Auth.Scopes;

/// <summary>
/// Standard OpenID Connect scope definitions, each unlocking its OpenID Connect Core §5.4 claims
/// in both the ID token and at the userinfo endpoint.
/// </summary>
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
        IdTokenClaims = ProfileClaims,
        UserInfoClaims = ProfileClaims,
    };

    /// <summary>
    /// Gets the standard <c>email</c> scope definition.
    /// </summary>
    public static ScopeDefinition Email { get; } = new()
    {
        Name = "email",
        IsDiscoverable = true,
        IdTokenClaims = EmailClaims,
        UserInfoClaims = EmailClaims,
    };

    /// <summary>
    /// Gets the standard <c>phone</c> scope definition.
    /// </summary>
    public static ScopeDefinition Phone { get; } = new()
    {
        Name = "phone",
        IsDiscoverable = true,
        IdTokenClaims = PhoneClaims,
        UserInfoClaims = PhoneClaims,
    };

    /// <summary>
    /// Gets the standard <c>address</c> scope definition.
    /// </summary>
    public static ScopeDefinition Address { get; } = new()
    {
        Name = "address",
        IsDiscoverable = true,
        IdTokenClaims = AddressClaims,
        UserInfoClaims = AddressClaims,
    };

    /// <summary>
    /// Gets all standard OpenID Connect scope definitions.
    /// </summary>
    public static IReadOnlyCollection<ScopeDefinition> All { get; } = Array.AsReadOnly([OpenId, Profile, Email, Phone, Address]);
}
