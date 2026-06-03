using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.Options;

namespace ZeeKayDa.Auth.AspNetCore.Endpoints;

/// <summary>
/// Registers the pre-alpha token endpoint (<c>connect/token</c>) that returns
/// <see cref="StatusCodes.Status501NotImplemented"/> until the real implementation lands.
/// </summary>
internal sealed class PreAlphaTokenEndpoint : IZeeKayDaEndpoint
{
    private readonly IOptions<AuthorizationServerOptions> _options;

    public PreAlphaTokenEndpoint(IOptions<AuthorizationServerOptions> options)
    {
        _options = options;
    }

    /// <inheritdoc/>
    public void Map(IEndpointRouteBuilder endpoints)
    {
        var issuerUri = EndpointRouteHelper.GetIssuerUri(_options);
        var endpointUri = EndpointRouteHelper.GetPublishedEndpointUri(
            issuerUri,
            _options.Value.TokenEndpoint.Uri,
            "connect/token");

        endpoints.MapPost(
                endpointUri.AbsolutePath,
                () => PreAlphaNotImplementedResult.Result)
            .RequireIssuerHost(endpointUri);
    }
}
