using ZeeKayDa.Auth;
using ZeeKayDa.Auth.Authorization;
using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.Clients;

/// <summary>
/// Framework-provided implementation of <see cref="IClientWithCredentials"/> for use with
/// <c>InMemoryClientRepository</c> and unit tests.
/// </summary>
/// <remarks>
/// <para>
/// This is a pure value object — no validation is performed in the constructor so that tests can
/// construct invalid instances to exercise the validator independently. All validation is
/// delegated to <c>IClientRegistrationValidator</c>.
/// </para>
/// <para>
/// Use the factory methods <see cref="CreateConfidential"/> and <see cref="CreatePublic"/> to
/// create correctly pre-configured instances; use object initialiser syntax for advanced or
/// test scenarios.
/// </para>
/// </remarks>
public sealed record Client : IClientWithCredentials
{
    /// <inheritdoc/>
    public required string ClientId { get; init; }

    /// <inheritdoc/>
    public IReadOnlyList<IClientCredential> Credentials { get; init; } = [];

    /// <inheritdoc/>
    public bool IsPublic { get; init; } = ClientDefaults.IsPublic;

    /// <inheritdoc/>
    public IReadOnlySet<string> RedirectUris { get; init; } = ClientDefaults.RedirectUris;

    /// <inheritdoc/>
    public IReadOnlySet<string> PostLogoutRedirectUris { get; init; } = ClientDefaults.PostLogoutRedirectUris;

    /// <inheritdoc/>
    public IReadOnlySet<string> AllowedScopes { get; init; } = ClientDefaults.AllowedScopes;

    /// <inheritdoc/>
    public IReadOnlySet<GrantType> AllowedGrantTypes { get; init; } = ClientDefaults.AllowedGrantTypes;

    /// <inheritdoc/>
    public IReadOnlySet<ResponseType> AllowedResponseTypes { get; init; } = ClientDefaults.AllowedResponseTypes;

    /// <inheritdoc/>
    public IReadOnlySet<ResponseMode> AllowedResponseModes { get; init; } = ClientDefaults.AllowedResponseModes;

    // Unset, it follows IsPublic, whichever order the initialiser sets them in.
    private readonly IReadOnlySet<string>? _allowedTokenEndpointAuthMethods;

    /// <inheritdoc/>
    public IReadOnlySet<string> AllowedTokenEndpointAuthMethods
    {
        get => _allowedTokenEndpointAuthMethods ?? ClientDefaults.AllowedTokenEndpointAuthMethods(IsPublic);
        init => _allowedTokenEndpointAuthMethods = value;
    }

    /// <inheritdoc/>
    public IReadOnlySet<PromptValue> AllowedPromptValues { get; init; } = ClientDefaults.AllowedPromptValues;

    /// <inheritdoc/>
    public bool EnableZkdErrorCodes { get; init; } = ClientDefaults.EnableZkdErrorCodes;

    /// <inheritdoc/>
    public string? DisplayName { get; init; }

    /// <inheritdoc/>
    public string? InitiateLoginUri { get; init; }

    /// <inheritdoc/>
    public bool RequireConsent { get; init; } = ClientDefaults.RequireConsent;

    /// <inheritdoc/>
    public bool SkipLogoutConfirmation { get; init; } = ClientDefaults.SkipLogoutConfirmation;

    /// <inheritdoc/>
    public bool RequirePkce { get; init; } = ClientDefaults.RequirePkce;

    /// <inheritdoc/>
    public IReadOnlySet<SigningAlgorithm>? AllowedSigningAlgorithms { get; init; }

    /// <inheritdoc/>
    public TimeSpan? AccessTokenLifetime { get; init; }

    /// <inheritdoc/>
    public TimeSpan? IdTokenLifetime { get; init; }

    /// <inheritdoc/>
    public IReadOnlySet<string> AdditionalIdTokenClaims { get; init; } = ClientDefaults.AdditionalClaims;

    /// <inheritdoc/>
    public IReadOnlySet<string> AdditionalUserInfoClaims { get; init; } = ClientDefaults.AdditionalClaims;

    /// <inheritdoc/>
    public IReadOnlySet<string> AdditionalAccessTokenClaims { get; init; } = ClientDefaults.AdditionalClaims;

    /// <summary>
    /// Creates a confidential client registration with the given pre-built credential.
    /// </summary>
    /// <param name="clientId">Unique client identifier.</param>
    /// <param name="credential">
    /// A pre-built credential (for example a <see cref="Pbkdf2ClientSecret"/>). The caller is
    /// responsible for hashing before passing it here.
    /// </param>
    /// <param name="redirectUris">Permitted redirect URIs.</param>
    /// <param name="postLogoutRedirectUris">Permitted post-logout redirect URIs.</param>
    /// <param name="allowedScopes">Scopes this client is permitted to request.</param>
    /// <remarks>
    /// Sets <see cref="IsPublic"/> to <see langword="false"/> and populates
    /// <see cref="Credentials"/> with the supplied credential. All other properties use their
    /// default values and can be overridden using <c>with</c> expressions.
    /// </remarks>
    public static Client CreateConfidential(
        string clientId,
        IClientCredential credential,
        IEnumerable<string> redirectUris,
        IEnumerable<string> postLogoutRedirectUris,
        IEnumerable<string> allowedScopes) =>
        CreateConfidentialWithoutCredential(clientId, redirectUris, postLogoutRedirectUris, allowedScopes) with
        {
            Credentials = [credential],
        };

    /// <summary>
    /// Creates a public client registration with no credentials.
    /// </summary>
    /// <param name="clientId">Unique client identifier.</param>
    /// <param name="redirectUris">Permitted redirect URIs.</param>
    /// <param name="postLogoutRedirectUris">Permitted post-logout redirect URIs.</param>
    /// <param name="allowedScopes">Scopes this client is permitted to request.</param>
    /// <remarks>
    /// <para>
    /// Sets <see cref="IsPublic"/> to <see langword="true"/>, <see cref="Credentials"/> to an
    /// empty list, and <see cref="AllowedTokenEndpointAuthMethods"/> to <c>{ "none" }</c>.
    /// All other properties use their default values and can be overridden using <c>with</c>
    /// expressions.
    /// </para>
    /// <para>
    /// The server accepts public clients only when it advertises <c>none</c>, which it does not by
    /// default: add <see cref="TokenEndpointAuthMethods.None"/> to
    /// <c>TokenEndpoint.AuthMethodsSupported</c>, or startup rejects the registration.
    /// </para>
    /// </remarks>
    public static Client CreatePublic(
        string clientId,
        IEnumerable<string> redirectUris,
        IEnumerable<string> postLogoutRedirectUris,
        IEnumerable<string> allowedScopes) =>
        new()
        {
            ClientId = clientId,
            Credentials = [],
            IsPublic = true,
            RedirectUris = new HashSet<string>(redirectUris, StringComparer.Ordinal),
            PostLogoutRedirectUris = new HashSet<string>(postLogoutRedirectUris, StringComparer.Ordinal),
            AllowedScopes = new HashSet<string>(allowedScopes, StringComparer.Ordinal),
        };

    // A confidential registration whose credential is added later — by the in-memory builder,
    // whose secret is hashed only when the repository is built. Sharing it with CreateConfidential
    // keeps both paths on the same defaults.
    internal static Client CreateConfidentialWithoutCredential(
        string clientId,
        IEnumerable<string> redirectUris,
        IEnumerable<string> postLogoutRedirectUris,
        IEnumerable<string> allowedScopes) =>
        new()
        {
            ClientId = clientId,
            Credentials = [],
            IsPublic = false,
            RedirectUris = new HashSet<string>(redirectUris, StringComparer.Ordinal),
            PostLogoutRedirectUris = new HashSet<string>(postLogoutRedirectUris, StringComparer.Ordinal),
            AllowedScopes = new HashSet<string>(allowedScopes, StringComparer.Ordinal),
        };
}
