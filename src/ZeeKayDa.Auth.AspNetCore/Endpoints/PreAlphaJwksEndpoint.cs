using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.Options;

namespace ZeeKayDa.Auth.AspNetCore.Endpoints;

/// <summary>
/// Registers the pre-alpha JWKS endpoint (<c>connect/jwks</c>) that returns
/// <see cref="StatusCodes.Status501NotImplemented"/> until the real implementation lands.
/// </summary>
internal sealed class PreAlphaJwksEndpoint : IZeeKayDaEndpoint
{
    private readonly IOptions<AuthorizationServerOptions> _options;

    public PreAlphaJwksEndpoint(IOptions<AuthorizationServerOptions> options)
    {
        _options = options;
    }

    /// <inheritdoc/>
    public void Map(IEndpointRouteBuilder endpoints)
    {
        var issuerUri = EndpointRouteHelper.GetIssuerUri(_options);
        var endpointUri = EndpointRouteHelper.GetPublishedEndpointUri(
            issuerUri,
            _options.Value.Jwks.Uri,
            "connect/jwks");

        endpoints.MapGet(
                endpointUri.AbsolutePath,
                () => PreAlphaNotImplementedResult.Result)
            .RequireIssuerHost(endpointUri);
    }
}
