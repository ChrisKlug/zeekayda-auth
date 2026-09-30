using ZeeKayDa.Auth.Authorization;
using ZeeKayDa.Auth.Clients;
using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.AspNetCore.Clients;

/// <summary>
/// The settings every client registered through <see cref="IInMemoryClientRegistrationBuilder"/>
/// can configure beyond its identity, redirect URIs and scopes.
/// </summary>
/// <remarks>
/// An instance is handed to the <c>configure</c> callback of
/// <see cref="IInMemoryClientRegistrationBuilder.AddPublic"/> or
/// <see cref="IInMemoryClientRegistrationBuilder.AddConfidential"/>, pre-filled with the values a
/// registration has when nothing is set. Collections are changed in place. A collection with a
/// default starts empty instead, and the default is applied only if the callback adds nothing, so a
/// client that names its values gets exactly those. The values are copied into the registration
/// when the callback returns; changing the instance after that has no effect.
/// </remarks>
public abstract class ClientOptions
{
    private protected ClientOptions(ClientRegistration defaults)
    {
        DisplayName = defaults.DisplayName;
        InitiateLoginUri = defaults.InitiateLoginUri;
        RequireConsent = defaults.RequireConsent;
        SkipLogoutConfirmation = defaults.SkipLogoutConfirmation;
        EnableZkdErrorCodes = defaults.EnableZkdErrorCodes;
        AllowedGrantTypes = new HashSet<GrantType>();
        AllowedResponseTypes = new HashSet<ResponseType>();
        AllowedResponseModes = new HashSet<ResponseMode>();
        AllowedPromptValues = new HashSet<PromptValue>(defaults.AllowedPromptValues);
        AllowedSigningAlgorithms = new HashSet<SigningAlgorithm>(
            defaults.AllowedSigningAlgorithms ?? Enumerable.Empty<SigningAlgorithm>());
        AccessTokenLifetime = defaults.AccessTokenLifetime;
        IdTokenLifetime = defaults.IdTokenLifetime;
        AdditionalIdTokenClaims = new HashSet<string>(defaults.AdditionalIdTokenClaims, StringComparer.Ordinal);
        AdditionalUserInfoClaims = new HashSet<string>(defaults.AdditionalUserInfoClaims, StringComparer.Ordinal);
        AdditionalAccessTokenClaims = new HashSet<string>(defaults.AdditionalAccessTokenClaims, StringComparer.Ordinal);
    }

    // Copies every collection, so a caller holding on to this instance cannot change the
    // registration after it has been handed to the repository.
    internal virtual ClientRegistration ApplyTo(ClientRegistration registration)
    {
        var grantTypes = OrDefault(AllowedGrantTypes, registration.AllowedGrantTypes);

        // Response types and modes serve the authorization endpoint only, so a client without the
        // code grant never uses them and gets none by default.
        var usesAuthorizationEndpoint = grantTypes.Contains(GrantType.AuthorizationCode);

        return registration with
        {
            DisplayName = DisplayName,
            InitiateLoginUri = InitiateLoginUri,
            RequireConsent = RequireConsent,
            SkipLogoutConfirmation = SkipLogoutConfirmation,
            EnableZkdErrorCodes = EnableZkdErrorCodes,
            AllowedGrantTypes = grantTypes,
            AllowedResponseTypes = OrDefault(AllowedResponseTypes, usesAuthorizationEndpoint ? registration.AllowedResponseTypes : []),
            AllowedResponseModes = OrDefault(AllowedResponseModes, usesAuthorizationEndpoint ? registration.AllowedResponseModes : []),
            AllowedPromptValues = new HashSet<PromptValue>(AllowedPromptValues),
            AllowedSigningAlgorithms = AllowedSigningAlgorithms.Count == 0
                ? null
                : new HashSet<SigningAlgorithm>(AllowedSigningAlgorithms),
            AccessTokenLifetime = AccessTokenLifetime,
            IdTokenLifetime = IdTokenLifetime,
            AdditionalIdTokenClaims = [.. AdditionalIdTokenClaims],
            AdditionalUserInfoClaims = [.. AdditionalUserInfoClaims],
            AdditionalAccessTokenClaims = [.. AdditionalAccessTokenClaims],
        };
    }

    /// <summary>A copy of what the callback configured, or of the default if it configured nothing.</summary>
    private protected static HashSet<T> OrDefault<T>(
        ISet<T> configured, IEnumerable<T> defaults, IEqualityComparer<T>? comparer = null) =>
        new(configured.Count > 0 ? configured : defaults, comparer);

    /// <inheritdoc cref="IClientMetadata.DisplayName"/>
    public string? DisplayName { get; set; }

    /// <inheritdoc cref="IClientMetadata.InitiateLoginUri"/>
    public string? InitiateLoginUri { get; set; }

    /// <summary>
    /// Whether the user must consent on the host's consent page before an authorization code is
    /// issued to this client. <see langword="true"/> by default.
    /// </summary>
    /// <remarks>
    /// Consent is what lets a user notice an authorization request they never started, so turning
    /// it off removes that protection for this client. Do so only for an operator's own
    /// first-party applications.
    /// </remarks>
    public bool RequireConsent { get; set; }

    /// <inheritdoc cref="IClientMetadata.SkipLogoutConfirmation"/>
    public bool SkipLogoutConfirmation { get; set; }

    /// <inheritdoc cref="IClientMetadata.EnableZkdErrorCodes"/>
    public bool EnableZkdErrorCodes { get; set; }

    /// <summary>
    /// OAuth 2.0 grant types this client is permitted to use. Starts empty; left empty, the client
    /// gets <see cref="GrantType.AuthorizationCode"/>.
    /// </summary>
    public ISet<GrantType> AllowedGrantTypes { get; }

    /// <summary>
    /// Response types this client is permitted to request. Starts empty; left empty, the client gets
    /// <see cref="ResponseType.Code"/> if it is allowed <see cref="GrantType.AuthorizationCode"/>,
    /// and none otherwise.
    /// </summary>
    public ISet<ResponseType> AllowedResponseTypes { get; }

    /// <summary>
    /// Response modes this client is permitted to request. Starts empty; left empty, the client gets
    /// <see cref="ResponseMode.Query"/>, the one mode the server's authorization endpoint answers
    /// with, if it is allowed <see cref="GrantType.AuthorizationCode"/>, and none otherwise.
    /// </summary>
    public ISet<ResponseMode> AllowedResponseModes { get; }

    /// <inheritdoc cref="IClientMetadata.AllowedPromptValues" path="/summary"/>
    public ISet<PromptValue> AllowedPromptValues { get; }

    /// <summary>
    /// JWS signing algorithms permitted for ID tokens issued to this client. Empty by default, which
    /// means the client inherits the server's advertised set.
    /// </summary>
    /// <remarks>
    /// When not empty, every entry must be in the server's advertised set; startup fails otherwise.
    /// </remarks>
    public ISet<SigningAlgorithm> AllowedSigningAlgorithms { get; }

    /// <inheritdoc cref="IClientMetadata.AccessTokenLifetime"/>
    public TimeSpan? AccessTokenLifetime { get; set; }

    /// <inheritdoc cref="IClientMetadata.IdTokenLifetime"/>
    public TimeSpan? IdTokenLifetime { get; set; }

    /// <inheritdoc cref="IClientMetadata.AdditionalIdTokenClaims"/>
    public ISet<string> AdditionalIdTokenClaims { get; }

    /// <inheritdoc cref="IClientMetadata.AdditionalUserInfoClaims"/>
    public ISet<string> AdditionalUserInfoClaims { get; }

    /// <inheritdoc cref="IClientMetadata.AdditionalAccessTokenClaims"/>
    public ISet<string> AdditionalAccessTokenClaims { get; }
}
