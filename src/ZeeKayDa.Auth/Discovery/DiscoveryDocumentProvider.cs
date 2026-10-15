using Microsoft.Extensions.Options;
using ZeeKayDa.Auth;
using ZeeKayDa.Auth.Authorization;
using ZeeKayDa.Auth.Claims;
using ZeeKayDa.Auth.Scopes;
using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.Discovery;

/// <summary>
/// Builds the <see cref="OpenIdConfigurationDocument"/> from the options, the scope repository,
/// the signing key ring and the registered client authenticators.
/// </summary>
/// <remarks>
/// Endpoint URIs default to paths under the issuer, combined as URIs so a path-bearing issuer
/// works. Signing algorithms come from the key ring on every read, so none is advertised without a key.
/// </remarks>
internal sealed class DiscoveryDocumentProvider : IDiscoveryDocumentProvider
{
    private const string ConnectAuthorize = "connect/authorize";
    private const string ConnectToken = "connect/token";
    private const string ConnectJwks = "connect/jwks";
    private const string ConnectEndSession = "connect/endsession";
    private const string ConnectUserInfo = "connect/userinfo";

    private readonly IOptions<AuthorizationServerOptions> _options;
    private readonly ValidatedScopeCatalog _scopes;
    private readonly SigningKeyRing _keyRing;
    private readonly AdvertisedAuthMethods _authMethods;

    public DiscoveryDocumentProvider(
        IOptions<AuthorizationServerOptions> options,
        ValidatedScopeCatalog scopes,
        SigningKeyRing keyRing,
        AdvertisedAuthMethods authMethods)
    {
        _options = options;
        _scopes = scopes;
        _keyRing = keyRing;
        _authMethods = authMethods;
    }

    /// <inheritdoc/>
    public async Task<OpenIdConfigurationDocument> GetDocumentAsync(CancellationToken cancellationToken = default)
    {
        var options = _options.Value;

        var issuerUri = new Uri(options.Issuer!);

        var scopes = await _scopes.GetScopesAsync(cancellationToken).ConfigureAwait(false);
        var interactive = InteractiveMetadata.For(options, issuerUri, scopes);

        return new OpenIdConfigurationDocument
        {
            Issuer = options.Issuer!,
            AuthorizationEndpoint = interactive.AuthorizationEndpoint,
            TokenEndpoint = options.TokenEndpoint.Uri
                ?? IssuerUriHelper.Combine(issuerUri, ConnectToken).AbsoluteUri,
            JwksUri = options.JwksEndpoint.Uri
                ?? IssuerUriHelper.Combine(issuerUri, ConnectJwks).AbsoluteUri,
            EndSessionEndpoint = interactive.EndSessionEndpoint,
            UserInfoEndpoint = interactive.UserInfoEndpoint,
            ResponseTypesSupported = interactive.ResponseTypesSupported,
            ScopesSupported = [.. scopes
                .Where(scope => scope.IsDiscoverable)
                .Select(scope => scope.Name)],
            ClaimsSupported = interactive.ClaimsSupported,
            ResponseModesSupported = interactive.ResponseModesSupported,
            GrantTypesSupported = [.. options.GrantTypesSupported],
            TokenEndpointAuthMethodsSupported = _authMethods.Methods,
            IdTokenSigningAlgValuesSupported = [_keyRing.Current.Algorithm],
            CodeChallengeMethodsSupported = interactive.CodeChallengeMethodsSupported,
            AuthorizationResponseIssParameterSupported = interactive.AuthorizationResponseIssParameterSupported,
        };
    }

    /// <summary>
    /// The metadata published only while the authorization code grant is served, <see langword="null"/>
    /// otherwise (RFC 8414 §2, Discovery §4.2): naming an endpoint that answers 404 is worse than omitting it.
    /// </summary>
    private sealed record InteractiveMetadata
    {
        /// <summary>What a host serving no such grant publishes: none of it.</summary>
        public static readonly InteractiveMetadata None = new();

        public string? AuthorizationEndpoint { get; init; }

        public string? EndSessionEndpoint { get; init; }

        public string? UserInfoEndpoint { get; init; }

        public IReadOnlyCollection<ResponseType>? ResponseTypesSupported { get; init; }

        public IReadOnlyCollection<ResponseMode>? ResponseModesSupported { get; init; }

        public IReadOnlyCollection<CodeChallengeMethod>? CodeChallengeMethodsSupported { get; init; }

        public IReadOnlyCollection<string>? ClaimsSupported { get; init; }

        public bool? AuthorizationResponseIssParameterSupported { get; init; }

        /// <summary>
        /// The ID token protocol claims plus what the discoverable scopes unlock in an ID token or
        /// at UserInfo; access token claims are for the resource server, not Discovery §3.
        /// </summary>
        /// <remarks>
        /// De-duplicated case-insensitively, as <see cref="Claims.ClaimSelection"/> groups them.
        /// </remarks>
        private static IReadOnlyCollection<string> ClaimsSupportedFrom(IReadOnlyCollection<ScopeDefinition> scopes) =>
            [.. IdTokenProtocolClaims.Names
                .Concat(scopes
                    .Where(scope => scope.IsDiscoverable)
                    .SelectMany(scope => scope.IdTokenClaims.Concat(scope.UserInfoClaims)))
                .Distinct(StringComparer.OrdinalIgnoreCase)];

        public static InteractiveMetadata For(
            AuthorizationServerOptions options,
            Uri issuerUri,
            IReadOnlyCollection<ScopeDefinition> scopes) =>
            options.GrantTypesSupported.Contains(GrantType.AuthorizationCode)
                ? new InteractiveMetadata
                {
                    AuthorizationEndpoint = options.AuthorizationEndpoint.Uri
                        ?? IssuerUriHelper.Combine(issuerUri, ConnectAuthorize).AbsoluteUri,
                    EndSessionEndpoint = options.EndSessionEndpoint.Uri
                        ?? IssuerUriHelper.Combine(issuerUri, ConnectEndSession).AbsoluteUri,
                    UserInfoEndpoint = options.UserInfoEndpoint.Uri
                        ?? IssuerUriHelper.Combine(issuerUri, ConnectUserInfo).AbsoluteUri,
                    ResponseTypesSupported = [.. options.Response.TypesSupported],
                    ResponseModesSupported = [.. options.Response.ModesSupported],
                    CodeChallengeMethodsSupported = options.AuthorizationEndpoint.CodeChallengeMethodsSupported is { } methods
                        ? [.. methods]
                        : null,
                    ClaimsSupported = ClaimsSupportedFrom(scopes),
                    AuthorizationResponseIssParameterSupported = true,
                }
                : None;
    }
}
