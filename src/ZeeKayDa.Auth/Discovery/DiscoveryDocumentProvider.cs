using Microsoft.Extensions.Options;
using ZeeKayDa.Auth;
using ZeeKayDa.Auth.Scopes;

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
/// URI can be overridden by setting the corresponding property on
/// <see cref="AuthorizationServerOptions"/>. Scope names published in
/// <c>scopes_supported</c> are sourced from the configured <see cref="Scopes.IScopeRepository"/>.
/// </remarks>
internal sealed class DiscoveryDocumentProvider : IDiscoveryDocumentProvider
{
    // Connect path segments used to derive default endpoint URIs from the issuer.
    private const string ConnectAuthorize = "connect/authorize";
    private const string ConnectToken = "connect/token";
    private const string ConnectJwks = "connect/jwks";

    private readonly IOptions<AuthorizationServerOptions> _options;
    private readonly IScopeRepository _scopeRepository;

    public DiscoveryDocumentProvider(
        IOptions<AuthorizationServerOptions> options,
        IScopeRepository scopeRepository)
    {
        _options = options;
        _scopeRepository = scopeRepository;
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
            AuthorizationEndpoint = options.AuthorizationEndpoint
                ?? IssuerUriHelper.Combine(issuerUri, ConnectAuthorize).AbsoluteUri,
            TokenEndpoint = options.TokenEndpoint
                ?? IssuerUriHelper.Combine(issuerUri, ConnectToken).AbsoluteUri,
            JwksUri = options.JwksUri
                ?? IssuerUriHelper.Combine(issuerUri, ConnectJwks).AbsoluteUri,
            ResponseTypesSupported = [.. options.ResponseTypesSupported],
            ScopesSupported = [.. scopes
                .Where(scope => scope.IsDiscoverable)
                .Select(scope => scope.Name)],
            ResponseModesSupported = [.. options.ResponseModesSupported],
            GrantTypesSupported = [.. options.GrantTypesSupported],
            TokenEndpointAuthMethodsSupported = [.. options.TokenEndpointAuthMethodsSupported],
            IdTokenSigningAlgValuesSupported = [.. options.IdTokenSigningAlgValuesSupported],
        };
    }
}
