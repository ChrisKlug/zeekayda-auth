using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.Options;

namespace ZeeKayDa.Auth.AspNetCore.Endpoints;

/// <summary>
/// Registers the pre-alpha authorization endpoint (<c>connect/authorize</c>) that returns
/// <see cref="StatusCodes.Status501NotImplemented"/> until the real implementation lands.
/// </summary>
internal sealed class PreAlphaAuthorizationEndpoint : IZeeKayDaEndpoint
{
    private readonly IOptions<AuthorizationServerOptions> _options;

    public PreAlphaAuthorizationEndpoint(IOptions<AuthorizationServerOptions> options)
    {
        _options = options;
    }

    /// <inheritdoc/>
    public void Map(IEndpointRouteBuilder endpoints)
    {
        var issuerUri = EndpointRouteHelper.GetIssuerUri(_options);
        var endpointUri = EndpointRouteHelper.GetPublishedEndpointUri(
            issuerUri,
            _options.Value.AuthorizationEndpoint.Uri,
            "connect/authorize");

        endpoints.MapMethods(
                endpointUri.AbsolutePath,
                [HttpMethods.Get, HttpMethods.Post],
                () => PreAlphaNotImplementedResult.Result)
            .RequireIssuerHost(endpointUri);
    }
}
