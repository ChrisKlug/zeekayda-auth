using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.Options;
using ZeeKayDa.Auth;

namespace ZeeKayDa.Auth.AspNetCore.Endpoints;

/// <summary>
/// Registers pre-alpha protocol endpoints advertised by discovery but not implemented yet.
/// </summary>
internal sealed class PreAlphaProtocolEndpoint : IZeeKayDaEndpoint
{
    private readonly IOptions<AuthorizationServerOptions> _options;

    public PreAlphaProtocolEndpoint(IOptions<AuthorizationServerOptions> options)
    {
        _options = options;
    }

    /// <inheritdoc/>
    public void Map(IEndpointRouteBuilder endpoints)
    {
        var options = _options.Value;
        var issuerUri = EndpointRouteHelper.GetIssuerUri(_options);
        var authorizationEndpoint = EndpointRouteHelper.GetPublishedEndpointUri(
            issuerUri,
            options.AuthorizationEndpoint,
            "connect/authorize");
        var tokenEndpoint = EndpointRouteHelper.GetPublishedEndpointUri(
            issuerUri,
            options.TokenEndpoint,
            "connect/token");
        var jwksUri = EndpointRouteHelper.GetPublishedEndpointUri(
            issuerUri,
            options.JwksUri,
            "connect/jwks");

        endpoints.MapMethods(
                EndpointRouteHelper.GetRoutePath(authorizationEndpoint),
                [HttpMethods.Get, HttpMethods.Post],
                NotImplemented)
            .RequireIssuerHost(authorizationEndpoint);

        endpoints.MapPost(
                EndpointRouteHelper.GetRoutePath(tokenEndpoint),
                NotImplemented)
            .RequireIssuerHost(tokenEndpoint);

        endpoints.MapGet(
                EndpointRouteHelper.GetRoutePath(jwksUri),
                NotImplemented)
            .RequireIssuerHost(jwksUri);
    }

    private static IResult NotImplemented()
        => Results.Problem(
            statusCode: StatusCodes.Status501NotImplemented,
            title: "Endpoint not implemented",
            detail: "ZeeKayDa.Auth is pre-alpha. This protocol endpoint is advertised for discovery shape stability but is not implemented yet.");
}
