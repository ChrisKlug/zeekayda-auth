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
internal sealed class TokenEndpoint : IZeeKayDaEndpoint
{
    private readonly IOptions<AuthorizationServerOptions> _options;

    public TokenEndpoint(IOptions<AuthorizationServerOptions> options)
    {
        ArgumentNullException.ThrowIfNull(options);
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
                (TokenRequestHandler handler, HttpContext context) => handler.HandleAsync(context))
            .RequireIssuerHost(endpointUri);
    }
}
