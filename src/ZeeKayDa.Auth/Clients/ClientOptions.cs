using ZeeKayDa.Auth.Authorization;
using ZeeKayDa.Auth.Clients;
using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.Clients;

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
    private protected ClientOptions()
    {
        DisplayName = ClientDefaults.DisplayName;
        InitiateLoginUri = ClientDefaults.InitiateLoginUri;
        AccessTokenLifetime = ClientDefaults.AccessTokenLifetime;
        IdTokenLifetime = ClientDefaults.IdTokenLifetime;
        RequireConsent = ClientDefaults.RequireConsent;
        SkipLogoutConfirmation = ClientDefaults.SkipLogoutConfirmation;
        EnableZkdErrorCodes = ClientDefaults.EnableZkdErrorCodes;
        AllowedGrantTypes = new HashSet<GrantType>();
        AllowedResponseTypes = new HashSet<ResponseType>();
        AllowedResponseModes = new HashSet<ResponseMode>();
        AllowedPromptValues = new HashSet<PromptValue>(ClientDefaults.AllowedPromptValues);
        AllowedSigningAlgorithms = new HashSet<SigningAlgorithm>(
            ClientDefaults.AllowedSigningAlgorithms ?? Enumerable.Empty<SigningAlgorithm>());
        AdditionalIdTokenClaims = new HashSet<string>(ClientDefaults.AdditionalClaims, StringComparer.Ordinal);
        AdditionalUserInfoClaims = new HashSet<string>(ClientDefaults.AdditionalClaims, StringComparer.Ordinal);
        AdditionalAccessTokenClaims = new HashSet<string>(ClientDefaults.AdditionalClaims, StringComparer.Ordinal);
    }

    // Copies every collection, so a caller holding on to this instance cannot change the
    // registration after it has been handed to the repository.
    internal virtual Client ApplyTo(Client registration)
    {
        var grantTypes = OrDefault(AllowedGrantTypes, registration.AllowedGrantTypes);

        return registration with
        {
            DisplayName = DisplayName,
            InitiateLoginUri = InitiateLoginUri,
            RequireConsent = RequireConsent,
            SkipLogoutConfirmation = SkipLogoutConfirmation,
            EnableZkdErrorCodes = EnableZkdErrorCodes,
            AllowedGrantTypes = grantTypes,
            AllowedResponseTypes = OrDefault(AllowedResponseTypes, registration.AllowedResponseTypes),
            AllowedResponseModes = OrDefault(AllowedResponseModes, registration.AllowedResponseModes),
            AllowedPromptValues = new HashSet<PromptValue>(AllowedPromptValues),
            AllowedSigningAlgorithms = AllowedSigningAlgorithms.Count == 0
                ? null
                : new HashSet<SigningAlgorithm>(AllowedSigningAlgorithms),
            AccessTokenLifetime = AccessTokenLifetime,
            IdTokenLifetime = IdTokenLifetime,
            AdditionalIdTokenClaims = new HashSet<string>(AdditionalIdTokenClaims, StringComparer.Ordinal),
            AdditionalUserInfoClaims = new HashSet<string>(AdditionalUserInfoClaims, StringComparer.Ordinal),
            AdditionalAccessTokenClaims = new HashSet<string>(AdditionalAccessTokenClaims, StringComparer.Ordinal),
        };
    }

    /// <summary>A copy of what the callback configured, or of the default if it configured nothing.</summary>
    private protected static HashSet<T> OrDefault<T>(
        ISet<T> configured, IEnumerable<T> defaults, IEqualityComparer<T>? comparer = null) =>
        new(configured.Count > 0 ? configured : defaults, comparer);

    /// <inheritdoc cref="IClient.DisplayName"/>
    public string? DisplayName { get; set; }

    /// <inheritdoc cref="IClient.InitiateLoginUri"/>
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

    /// <inheritdoc cref="IClient.SkipLogoutConfirmation"/>
    public bool SkipLogoutConfirmation { get; set; }

    /// <inheritdoc cref="IClient.EnableZkdErrorCodes"/>
    public bool EnableZkdErrorCodes { get; set; }

    /// <summary>
    /// OAuth 2.0 grant types this client is permitted to use. Starts empty; left empty, the client
    /// gets <see cref="GrantType.AuthorizationCode"/>.
    /// </summary>
    public ISet<GrantType> AllowedGrantTypes { get; }

    /// <summary>
    /// Response types this client is permitted to request. Starts empty; left empty, the client gets
    /// <see cref="ResponseType.Code"/>, whatever its grant types.
    /// </summary>
    public ISet<ResponseType> AllowedResponseTypes { get; }

    /// <summary>
    /// Response modes this client is permitted to request. Starts empty; left empty, the client gets
    /// <see cref="ResponseMode.Query"/>, the one mode the server's authorization endpoint answers
    /// with, whatever its grant types.
    /// </summary>
    public ISet<ResponseMode> AllowedResponseModes { get; }

    /// <inheritdoc cref="IClient.AllowedPromptValues" path="/summary"/>
    public ISet<PromptValue> AllowedPromptValues { get; }

    /// <summary>
    /// JWS signing algorithms permitted for ID tokens issued to this client. Empty by default, which
    /// means the client inherits the server's advertised set.
    /// </summary>
    /// <remarks>
    /// When not empty, every entry must be in the server's advertised set; startup fails otherwise.
    /// </remarks>
    public ISet<SigningAlgorithm> AllowedSigningAlgorithms { get; }

    /// <inheritdoc cref="IClient.AccessTokenLifetime"/>
    public TimeSpan? AccessTokenLifetime { get; set; }

    /// <inheritdoc cref="IClient.IdTokenLifetime"/>
    public TimeSpan? IdTokenLifetime { get; set; }

    /// <inheritdoc cref="IClient.AdditionalIdTokenClaims"/>
    public ISet<string> AdditionalIdTokenClaims { get; }

    /// <inheritdoc cref="IClient.AdditionalUserInfoClaims"/>
    public ISet<string> AdditionalUserInfoClaims { get; }

    /// <inheritdoc cref="IClient.AdditionalAccessTokenClaims"/>
    public ISet<string> AdditionalAccessTokenClaims { get; }
}
