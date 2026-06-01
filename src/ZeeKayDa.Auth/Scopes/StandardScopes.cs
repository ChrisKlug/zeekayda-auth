namespace ZeeKayDa.Auth.Scopes;

/// <summary>
/// Standard OpenID Connect scope definitions.
/// </summary>
public static class StandardScopes
{
    private static readonly IReadOnlyCollection<string> OpenIdIdTokenClaims = Array.AsReadOnly(["sub"]);
    private static readonly IReadOnlyCollection<string> ProfileIdTokenClaims = Array.AsReadOnly(["name", "family_name", "given_name", "middle_name", "nickname", "preferred_username", "profile", "picture", "website", "gender", "birthdate", "zoneinfo", "locale", "updated_at"]);
    private static readonly IReadOnlyCollection<string> EmailIdTokenClaims = Array.AsReadOnly(["email", "email_verified"]);
    private static readonly IReadOnlyCollection<string> PhoneIdTokenClaims = Array.AsReadOnly(["phone_number", "phone_number_verified"]);
    private static readonly IReadOnlyCollection<string> AddressIdTokenClaims = Array.AsReadOnly(["address"]);

    /// <summary>
    /// Gets the standard <c>openid</c> scope definition.
    /// </summary>
    public static ScopeDefinition OpenId { get; } = new()
    {
        Name = "openid",
        IsDiscoverable = true,
        IdTokenClaims = OpenIdIdTokenClaims,
    };

    /// <summary>
    /// Gets the standard <c>profile</c> scope definition.
    /// </summary>
    public static ScopeDefinition Profile { get; } = new()
    {
        Name = "profile",
        IsDiscoverable = true,
        IdTokenClaims = ProfileIdTokenClaims,
    };

    /// <summary>
    /// Gets the standard <c>email</c> scope definition.
    /// </summary>
    public static ScopeDefinition Email { get; } = new()
    {
        Name = "email",
        IsDiscoverable = true,
        IdTokenClaims = EmailIdTokenClaims,
    };

    /// <summary>
    /// Gets the standard <c>phone</c> scope definition.
    /// </summary>
    public static ScopeDefinition Phone { get; } = new()
    {
        Name = "phone",
        IsDiscoverable = true,
        IdTokenClaims = PhoneIdTokenClaims,
    };

    /// <summary>
    /// Gets the standard <c>address</c> scope definition.
    /// </summary>
    public static ScopeDefinition Address { get; } = new()
    {
        Name = "address",
        IsDiscoverable = true,
        IdTokenClaims = AddressIdTokenClaims,
    };

    /// <summary>
    /// Gets all standard OpenID Connect scope definitions.
    /// </summary>
    public static IReadOnlyCollection<ScopeDefinition> All { get; } = Array.AsReadOnly([OpenId, Profile, Email, Phone, Address]);
}
