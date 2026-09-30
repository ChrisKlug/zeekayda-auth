using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.Options;
using ZeeKayDa.Auth.AspNetCore.Tokens;

namespace ZeeKayDa.Auth.AspNetCore.Endpoints;

/// <summary>
/// The token endpoint (<c>/connect/token</c>, POST only per RFC 6749 §3.2). Exchanges an
/// authorization code for an access token and an ID token, with client authentication and
/// PKCE verification for every client.
/// </summary>
/// <remarks>
/// Mapped unconditionally: discovery publishes <c>token_endpoint</c> unconditionally too, because
/// RFC 8414 §2 requires it, so the metadata and the route always agree.
/// </remarks>
internal sealed class TokenEndpoint(IOptions<AuthorizationServerOptions> options) : IZeeKayDaEndpoint
{
    /// <inheritdoc/>
    public void Map(IEndpointRouteBuilder endpoints)
    {
        var issuerUri = EndpointRouteHelper.GetIssuerUri(options);
        var endpointUri = EndpointRouteHelper.GetPublishedEndpointUri(
            issuerUri,
            options.Value.TokenEndpoint.Uri,
            "connect/token");

        endpoints.MapPost(
                endpointUri.AbsolutePath,
                (TokenRequestHandler handler, HttpContext context) => handler.HandleAsync(context))
            .RequireIssuerHost(endpointUri)
            // AllowAnonymous so a host-wide authorization fallback policy cannot turn the token
            // endpoint into a host-scheme challenge: OAuth client authentication is its own.
            .AllowAnonymous();
    }
}
