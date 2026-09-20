using Microsoft.Extensions.Options;
using ZeeKayDa.Auth;
using ZeeKayDa.Auth.Authorization;
using ZeeKayDa.Auth.Claims;
using ZeeKayDa.Auth.Scopes;
using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.Discovery;

/// <summary>
/// Default implementation of <see cref="IDiscoveryDocumentProvider"/> that maps
/// <see cref="AuthorizationServerOptions"/> and <see cref="Scopes.IScopeRepository"/> to an
/// <see cref="OpenIdConfigurationDocument"/>.
/// </summary>
/// <remarks>
/// Endpoint URIs for <c>authorization_endpoint</c>, <c>token_endpoint</c>, <c>jwks_uri</c>,
/// <c>end_session_endpoint</c> and <c>userinfo_endpoint</c> are derived from <see cref="AuthorizationServerOptions.Issuer"/> using
/// <see cref="Uri"/> combination semantics — never string concatenation — so that path-bearing
/// issuers (e.g. <c>https://auth.example.com/tenant1</c>) are handled correctly. Any individual
/// URI can be overridden by setting the corresponding property on the respective option group
/// (<see cref="AuthorizationEndpointOptions.Uri"/>, <see cref="TokenEndpointOptions.Uri"/>, <see cref="JwksEndpointOptions.Uri"/>,
/// <see cref="EndSessionEndpointOptions.Uri"/>, <see cref="Claims.UserInfoEndpointOptions.Uri"/>).
/// Scope names published in <c>scopes_supported</c> are sourced from the configured
/// <see cref="Scopes.IScopeRepository"/>. <c>id_token_signing_alg_values_supported</c> is derived
/// from the <see cref="ISigningKeyRing"/>'s current key set on every read — never from operator
/// configuration alone — so the server cannot advertise an algorithm it has no key for. A host with
/// no signing key source registered fails startup (<c>signing.key_ring.missing</c>) rather than
/// reaching this type.
/// </remarks>
internal sealed class DiscoveryDocumentProvider : IDiscoveryDocumentProvider
{
    // Connect path segments used to derive default endpoint URIs from the issuer.
    private const string ConnectAuthorize = "connect/authorize";
    private const string ConnectToken = "connect/token";
    private const string ConnectJwks = "connect/jwks";
    private const string ConnectEndSession = "connect/endsession";
    private const string ConnectUserInfo = "connect/userinfo";

    private readonly IOptions<AuthorizationServerOptions> _options;
    private readonly IScopeRepository _scopeRepository;
    private readonly ISigningKeyRing _keyRing;

    public DiscoveryDocumentProvider(
        IOptions<AuthorizationServerOptions> options,
        IScopeRepository scopeRepository,
        ISigningKeyRing keyRing)
    {
        _options = options;
        _scopeRepository = scopeRepository;
        _keyRing = keyRing;
    }

    /// <inheritdoc/>
    public async ValueTask<OpenIdConfigurationDocument> GetDocumentAsync(CancellationToken cancellationToken = default)
    {
        var options = _options.Value;

        // The issuer is validated at startup; by the time this method is called it is safe to use.
        var issuerUri = new Uri(options.Issuer!);

        var scopes = await _scopeRepository.GetScopesAsync(cancellationToken).ConfigureAwait(false);
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
            TokenEndpointAuthMethodsSupported = [.. options.TokenEndpoint.AuthMethodsSupported
                .Distinct(StringComparer.Ordinal)],
            IdTokenSigningAlgValuesSupported = [.. AdvertisedSigningAlgorithms.Resolve(
                _keyRing.Current, options.IdToken.AdvertisedSigningAlgorithms)],
            CodeChallengeMethodsSupported = interactive.CodeChallengeMethodsSupported,
        };
    }

    /// <summary>
    /// The metadata a host publishes only while it serves a grant that uses the authorization
    /// endpoint; every field is <see langword="null"/> otherwise. RFC 8414 §2 lets the endpoint be
    /// omitted on that condition, and OpenID Connect Discovery §4.2 omits a zero-element claim
    /// rather than publishing an empty array: metadata naming an endpoint that answers 404, or a
    /// response type nothing serves, is worse than metadata without.
    /// <c>claims_supported</c> rides the same gate: an ID token is born from the authorization
    /// code grant, and a host without it answers no UserInfo request either, so it can supply
    /// none of those claims.
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

        /// <summary>
        /// The claims the server may supply: what the discoverable scopes unlock in an ID token or
        /// at the UserInfo endpoint, plus the protocol claims an ID token carries.
        /// </summary>
        /// <remarks>
        /// <see cref="ScopeDefinition.AccessTokenClaims"/> are excluded, because Discovery §3 is
        /// about the ID token and the UserInfo endpoint and an access token is for the resource
        /// server. A scope hidden from discovery hides its claims too, the same filter
        /// <c>scopes_supported</c> uses. Names are de-duplicated case-insensitively, because
        /// <see cref="Claims.ClaimSelection"/> groups them that way: two scopes spelling a claim
        /// <c>email</c> and <c>Email</c> unlock one claim, so the document must not name two.
        /// </remarks>
        /// <remarks>
        /// A null list and a null or blank entry are both read as nothing, the way
        /// <c>ClaimSelectionPlan.Wanted</c> and <see cref="Clients.ClientClaimAdditions"/> already
        /// read them. <see cref="ScopeDefinition"/> declares these lists non-nullable and
        /// <c>InMemoryScopeRepository</c> refuses a bad claim name at construction, but a custom
        /// <see cref="IScopeRepository"/> answers neither to the type system at runtime nor to that
        /// constructor. Without this, a repository that issues tokens perfectly well would make an
        /// unauthenticated GET of the discovery document throw, or put a JSON <c>null</c> into a
        /// member Discovery §3 defines as an array of strings.
        /// </remarks>
        private static IReadOnlyCollection<string> ClaimsSupportedFrom(IReadOnlyCollection<ScopeDefinition> scopes) =>
            [.. IdTokenProtocolClaims.Names
                .Concat(scopes
                    .Where(scope => scope.IsDiscoverable)
                    .SelectMany(scope => (scope.IdTokenClaims ?? []).Concat(scope.UserInfoClaims ?? [])))
                .Where(claim => !string.IsNullOrWhiteSpace(claim))
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
                }
                : None;
    }
}
