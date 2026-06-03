using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.Options;
using ZeeKayDa.Auth;
using ZeeKayDa.Auth.Discovery;

namespace ZeeKayDa.Auth.AspNetCore.Endpoints;

/// <summary>
/// Registers the OpenID Connect Discovery 1.0 endpoint
/// (<c>GET /.well-known/openid-configuration</c>, or the path-prefixed equivalent when the
/// issuer carries a path component).
/// </summary>
internal sealed class DiscoveryEndpoint : IZeeKayDaEndpoint
{
    // Appended to the issuer path to form the discovery document URL per OIDC Discovery §4.1.
    private const string WellKnownSuffix = "/.well-known/openid-configuration";

    private readonly IOptions<AuthorizationServerOptions> _options;

    public DiscoveryEndpoint(IOptions<AuthorizationServerOptions> options)
    {
        _options = options;
    }

    /// <inheritdoc/>
    public void Map(IEndpointRouteBuilder endpoints)
    {
        // Derive the registration path from the issuer's path component so that a path-bearing
        // issuer (e.g. https://auth.example.com/tenant1) registers at
        // /tenant1/.well-known/openid-configuration rather than at the root, as required by
        // OIDC Discovery 1.0 §4.1 and RFC 9207 §4.
        var issuerUri = EndpointRouteHelper.GetIssuerUri(_options);
        var routePath = EndpointRouteHelper.GetIssuerPathPrefixedRoute(issuerUri, WellKnownSuffix);

        endpoints.MapGet(routePath, Handle).RequireIssuerHost(issuerUri);
    }

    private async ValueTask<IResult> Handle(
        IDiscoveryDocumentProvider provider,
        HttpContext context)
    {
        // Cache-Control set directly in the handler per ADR §8 so that the behaviour is
        // co-located with the endpoint and trivially verifiable in tests without a pipeline.
        var maxAge = _options.Value.Discovery.CacheMaxAgeSeconds;
        context.Response.Headers.CacheControl = maxAge > 0
            ? $"public, max-age={maxAge}, must-revalidate"
            : "no-store";

        // Wildcard CORS origin so browser-based OIDC clients can fetch the discovery document.
        context.Response.Headers.AccessControlAllowOrigin = "*";

        var document = await provider.GetDocumentAsync(context.RequestAborted).ConfigureAwait(false);
        return Results.Json(document);
    }
}
