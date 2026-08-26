using Microsoft.Extensions.Options;
using ZeeKayDa.Auth;
using ZeeKayDa.Auth.Authorization;
using ZeeKayDa.Auth.Scopes;
using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.Discovery;

/// <summary>
/// Default implementation of <see cref="IDiscoveryDocumentProvider"/> that maps
/// <see cref="AuthorizationServerOptions"/> and <see cref="Scopes.IScopeRepository"/> to an
/// <see cref="OpenIdConfigurationDocument"/>.
/// </summary>
/// <remarks>
/// Endpoint URIs for <c>authorization_endpoint</c>, <c>token_endpoint</c>, and <c>jwks_uri</c>
/// are derived from <see cref="AuthorizationServerOptions.Issuer"/> using
/// <see cref="Uri"/> combination semantics — never string concatenation — so that path-bearing
/// issuers (e.g. <c>https://auth.example.com/tenant1</c>) are handled correctly. Any individual
/// URI can be overridden by setting the corresponding property on the respective option group
/// (<see cref="AuthorizationEndpointOptions.Uri"/>, <see cref="TokenEndpointOptions.Uri"/>, <see cref="JwksEndpointOptions.Uri"/>).
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

        return new OpenIdConfigurationDocument
        {
            Issuer = options.Issuer!,
            AuthorizationEndpoint = options.AuthorizationEndpoint.Uri
                ?? IssuerUriHelper.Combine(issuerUri, ConnectAuthorize).AbsoluteUri,
            TokenEndpoint = options.TokenEndpoint.Uri
                ?? IssuerUriHelper.Combine(issuerUri, ConnectToken).AbsoluteUri,
            JwksUri = options.JwksEndpoint.Uri
                ?? IssuerUriHelper.Combine(issuerUri, ConnectJwks).AbsoluteUri,
            ResponseTypesSupported = [.. options.Response.TypesSupported],
            ScopesSupported = [.. scopes
                .Where(scope => scope.IsDiscoverable)
                .Select(scope => scope.Name)],
            ResponseModesSupported = [.. options.Response.ModesSupported],
            GrantTypesSupported = [.. options.GrantTypesSupported],
            TokenEndpointAuthMethodsSupported = [.. options.TokenEndpoint.AuthMethodsSupported
                .Distinct(StringComparer.Ordinal)],
            IdTokenSigningAlgValuesSupported = [.. AdvertisedSigningAlgorithms.Resolve(
                _keyRing.Current, options.IdToken.AdvertisedSigningAlgorithms)],
            CodeChallengeMethodsSupported = options.AuthorizationEndpoint.CodeChallengeMethodsSupported is { } methods
                ? [.. methods]
                : null,
        };
    }
}
