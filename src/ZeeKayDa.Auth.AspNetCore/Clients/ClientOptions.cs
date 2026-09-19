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
/// registration has when nothing is set. Collections are changed in place. The values are copied
/// into the registration when the callback returns; changing the instance after that has no effect.
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
        AllowedGrantTypes = new HashSet<GrantType>(defaults.AllowedGrantTypes);
        AllowedResponseTypes = new HashSet<ResponseType>(defaults.AllowedResponseTypes);
        AllowedResponseModes = new HashSet<ResponseMode>(defaults.AllowedResponseModes);
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
    internal virtual ClientRegistration ApplyTo(ClientRegistration registration) => registration with
    {
        DisplayName = DisplayName,
        InitiateLoginUri = InitiateLoginUri,
        RequireConsent = RequireConsent,
        SkipLogoutConfirmation = SkipLogoutConfirmation,
        EnableZkdErrorCodes = EnableZkdErrorCodes,
        AllowedGrantTypes = new HashSet<GrantType>(AllowedGrantTypes),
        AllowedResponseTypes = new HashSet<ResponseType>(AllowedResponseTypes),
        AllowedResponseModes = new HashSet<ResponseMode>(AllowedResponseModes),
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
    /// OAuth 2.0 grant types this client is permitted to use. Contains
    /// <see cref="GrantType.AuthorizationCode"/> by default.
    /// </summary>
    public ISet<GrantType> AllowedGrantTypes { get; }

    /// <summary>
    /// Response types this client is permitted to request. Contains <see cref="ResponseType.Code"/>
    /// by default.
    /// </summary>
    public ISet<ResponseType> AllowedResponseTypes { get; }

    /// <summary>
    /// Response modes this client is permitted to request. Contains <see cref="ResponseMode.Query"/>
    /// by default, the one mode the server's authorization endpoint answers with.
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
