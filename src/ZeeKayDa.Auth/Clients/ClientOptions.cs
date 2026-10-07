using ZeeKayDa.Auth.Authorization;
using ZeeKayDa.Auth.Clients;
using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.Clients;

/// <summary>
/// The settings every client registered through <see cref="InMemoryClientRegistrationBuilder"/> can
/// configure.
/// </summary>
/// <remarks>
/// An instance is handed to the <c>configure</c> callback of
/// <see cref="InMemoryClientRegistrationBuilder.AddPublic"/> or
/// <see cref="InMemoryClientRegistrationBuilder.AddConfidential"/>, or bound from a configuration
/// section, pre-filled with the values a registration has when nothing is set. Every collection
/// starts empty. A collection with a default gets it only if nothing is added, so a client that names
/// its values gets exactly those. The values are copied into the registration when the callback
/// returns; changing the instance after that has no effect.
/// </remarks>
public abstract class ClientOptions
{
    private protected ClientOptions()
    {
    }

    internal abstract Client ToClient(string clientId);

    // Copies every collection, so a caller holding on to this instance cannot change the
    // registration after it has been handed to the repository.
    private protected Client ToClient(string clientId, bool isPublic) => new()
    {
        ClientId = clientId,
        IsPublic = isPublic,
        RedirectUris = new HashSet<string>(RedirectUris, StringComparer.Ordinal),
        PostLogoutRedirectUris = new HashSet<string>(PostLogoutRedirectUris, StringComparer.Ordinal),
        AllowedScopes = new HashSet<string>(AllowedScopes, StringComparer.Ordinal),
        DisplayName = DisplayName,
        InitiateLoginUri = InitiateLoginUri,
        RequireConsent = RequireConsent,
        SkipLogoutConfirmation = SkipLogoutConfirmation,
        EnableZkdErrorCodes = EnableZkdErrorCodes,
        AllowedGrantTypes = OrDefault(AllowedGrantTypes, ClientDefaults.AllowedGrantTypes),
        AllowedResponseTypes = OrDefault(AllowedResponseTypes, ClientDefaults.AllowedResponseTypes),
        AllowedResponseModes = OrDefault(AllowedResponseModes, ClientDefaults.AllowedResponseModes),
        AllowedPromptValues = OrDefault(AllowedPromptValues, ClientDefaults.AllowedPromptValues),
        AllowedSigningAlgorithms = AllowedSigningAlgorithms.Count == 0
            ? ClientDefaults.AllowedSigningAlgorithms
            : new HashSet<SigningAlgorithm>(AllowedSigningAlgorithms),
        AccessTokenLifetime = AccessTokenLifetime,
        IdTokenLifetime = IdTokenLifetime,
        AdditionalIdTokenClaims = new HashSet<string>(AdditionalIdTokenClaims, StringComparer.Ordinal),
        AdditionalUserInfoClaims = new HashSet<string>(AdditionalUserInfoClaims, StringComparer.Ordinal),
        AdditionalAccessTokenClaims = new HashSet<string>(AdditionalAccessTokenClaims, StringComparer.Ordinal),
    };

    /// <summary>A copy of what was configured, or of the default if nothing was.</summary>
    private protected static HashSet<T> OrDefault<T>(
        ISet<T> configured, IEnumerable<T> defaults, IEqualityComparer<T>? comparer = null) =>
        new(configured.Count > 0 ? configured : defaults, comparer);

    /// <inheritdoc cref="IClient.RedirectUris"/>
    public ISet<string> RedirectUris { get; } = new HashSet<string>(StringComparer.Ordinal);

    /// <inheritdoc cref="IClient.PostLogoutRedirectUris"/>
    public ISet<string> PostLogoutRedirectUris { get; } = new HashSet<string>(StringComparer.Ordinal);

    /// <inheritdoc cref="IClient.AllowedScopes"/>
    public ISet<string> AllowedScopes { get; } = new HashSet<string>(StringComparer.Ordinal);

    /// <inheritdoc cref="IClient.DisplayName"/>
    public string? DisplayName { get; set; } = ClientDefaults.DisplayName;

    /// <inheritdoc cref="IClient.InitiateLoginUri"/>
    public string? InitiateLoginUri { get; set; } = ClientDefaults.InitiateLoginUri;

    /// <summary>
    /// Whether the user must consent on the host's consent page before an authorization code is
    /// issued to this client. <see langword="true"/> by default.
    /// </summary>
    /// <remarks>
    /// Consent is what lets a user notice an authorization request they never started, so turning
    /// it off removes that protection for this client. Do so only for an operator's own
    /// first-party applications.
    /// </remarks>
    public bool RequireConsent { get; set; } = ClientDefaults.RequireConsent;

    /// <inheritdoc cref="IClient.SkipLogoutConfirmation"/>
    public bool SkipLogoutConfirmation { get; set; } = ClientDefaults.SkipLogoutConfirmation;

    /// <inheritdoc cref="IClient.EnableZkdErrorCodes"/>
    public bool EnableZkdErrorCodes { get; set; } = ClientDefaults.EnableZkdErrorCodes;

    /// <summary>
    /// OAuth 2.0 grant types this client is permitted to use. Starts empty; left empty, the client
    /// gets <see cref="GrantType.AuthorizationCode"/>.
    /// </summary>
    public ISet<GrantType> AllowedGrantTypes { get; } = new HashSet<GrantType>();

    /// <summary>
    /// Response types this client is permitted to request. Starts empty; left empty, the client gets
    /// <see cref="ResponseType.Code"/>, whatever its grant types.
    /// </summary>
    public ISet<ResponseType> AllowedResponseTypes { get; } = new HashSet<ResponseType>();

    /// <summary>
    /// Response modes this client is permitted to request. Starts empty; left empty, the client gets
    /// <see cref="ResponseMode.Query"/>, the one mode the server's authorization endpoint answers
    /// with, whatever its grant types.
    /// </summary>
    public ISet<ResponseMode> AllowedResponseModes { get; } = new HashSet<ResponseMode>();

    /// <inheritdoc cref="IClient.AllowedPromptValues" path="/summary"/>
    public ISet<PromptValue> AllowedPromptValues { get; } = new HashSet<PromptValue>();

    /// <summary>
    /// JWS signing algorithms this client accepts for its ID tokens. Empty by default, which accepts
    /// whatever the server signs with.
    /// </summary>
    /// <remarks>
    /// When not empty, it must contain the algorithm the server signs with; startup fails otherwise.
    /// Any other entry has no effect and is warned about once.
    /// </remarks>
    public ISet<SigningAlgorithm> AllowedSigningAlgorithms { get; } = new HashSet<SigningAlgorithm>();

    /// <inheritdoc cref="IClient.AccessTokenLifetime"/>
    public TimeSpan? AccessTokenLifetime { get; set; } = ClientDefaults.AccessTokenLifetime;

    /// <inheritdoc cref="IClient.IdTokenLifetime"/>
    public TimeSpan? IdTokenLifetime { get; set; } = ClientDefaults.IdTokenLifetime;

    /// <inheritdoc cref="IClient.AdditionalIdTokenClaims"/>
    public ISet<string> AdditionalIdTokenClaims { get; } = new HashSet<string>(StringComparer.Ordinal);

    /// <inheritdoc cref="IClient.AdditionalUserInfoClaims"/>
    public ISet<string> AdditionalUserInfoClaims { get; } = new HashSet<string>(StringComparer.Ordinal);

    /// <inheritdoc cref="IClient.AdditionalAccessTokenClaims"/>
    public ISet<string> AdditionalAccessTokenClaims { get; } = new HashSet<string>(StringComparer.Ordinal);
}
