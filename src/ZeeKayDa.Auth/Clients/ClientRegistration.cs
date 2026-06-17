using ZeeKayDa.Auth;
using ZeeKayDa.Auth.Authorization;
using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.Clients;

/// <summary>
/// Framework-provided implementation of <see cref="IClientRegistration"/> for use with
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
public sealed record ClientRegistration : IClientRegistration
{
    /// <inheritdoc/>
    public required string ClientId { get; init; }

    /// <inheritdoc/>
    public required IReadOnlyList<IClientCredential> Credentials { get; init; }

    /// <inheritdoc/>
    public required bool IsPublic { get; init; }

    /// <inheritdoc/>
    public required IReadOnlySet<string> RedirectUris { get; init; }

    /// <inheritdoc/>
    public required IReadOnlySet<string> PostLogoutRedirectUris { get; init; }

    /// <inheritdoc/>
    public IReadOnlySet<string> AllowedScopes { get; init; }
        = new HashSet<string>(StringComparer.Ordinal);

    /// <inheritdoc/>
    public IReadOnlySet<GrantType> AllowedGrantTypes { get; init; }
        = new HashSet<GrantType> { GrantType.AuthorizationCode };

    /// <inheritdoc/>
    public IReadOnlySet<ResponseType> AllowedResponseTypes { get; init; }
        = new HashSet<ResponseType> { ResponseType.Code };

    /// <inheritdoc/>
    public IReadOnlySet<ResponseMode> AllowedResponseModes { get; init; }
        = new HashSet<ResponseMode> { ResponseMode.Query, ResponseMode.FormPost };

    /// <inheritdoc/>
    public IReadOnlySet<string> AllowedTokenEndpointAuthMethods { get; init; }
        = new HashSet<string>(StringComparer.Ordinal) { TokenEndpointAuthMethods.ClientSecretBasic };

    /// <inheritdoc/>
    public IReadOnlySet<PromptValue> AllowedPromptValues { get; init; }
        = new HashSet<PromptValue>();

    /// <inheritdoc/>
    public bool EnableZkdErrorCodes { get; init; }

    /// <inheritdoc/>
    public IReadOnlySet<SigningAlgorithm>? AllowedSigningAlgorithms { get; init; }

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
    public static ClientRegistration CreateConfidential(
        string clientId,
        IClientCredential credential,
        IEnumerable<string> redirectUris,
        IEnumerable<string> postLogoutRedirectUris,
        IEnumerable<string> allowedScopes) =>
        new()
        {
            ClientId = clientId,
            Credentials = [credential],
            IsPublic = false,
            RedirectUris = new HashSet<string>(redirectUris, StringComparer.Ordinal),
            PostLogoutRedirectUris = new HashSet<string>(postLogoutRedirectUris, StringComparer.Ordinal),
            AllowedScopes = new HashSet<string>(allowedScopes, StringComparer.Ordinal),
        };

    /// <summary>
    /// Creates a public client registration with no credentials.
    /// </summary>
    /// <param name="clientId">Unique client identifier.</param>
    /// <param name="redirectUris">Permitted redirect URIs.</param>
    /// <param name="postLogoutRedirectUris">Permitted post-logout redirect URIs.</param>
    /// <param name="allowedScopes">Scopes this client is permitted to request.</param>
    /// <remarks>
    /// Sets <see cref="IsPublic"/> to <see langword="true"/>, <see cref="Credentials"/> to an
    /// empty list, and <see cref="AllowedTokenEndpointAuthMethods"/> to <c>{ "none" }</c>.
    /// All other properties use their default values and can be overridden using <c>with</c>
    /// expressions.
    /// </remarks>
    public static ClientRegistration CreatePublic(
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
            AllowedTokenEndpointAuthMethods = new HashSet<string>(StringComparer.Ordinal)
                { TokenEndpointAuthMethods.None },
        };
}
