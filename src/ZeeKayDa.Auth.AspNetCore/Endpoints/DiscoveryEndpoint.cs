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
        var issuer = _options.Value.Issuer;

        if (string.IsNullOrWhiteSpace(issuer))
        {
            // Fail fast with a clear message; ValidateOnStart will also surface this, but Map()
            // is called during route registration which can happen before hosted services start.
            throw new InvalidOperationException(
                "AuthorizationServerOptions.Issuer must be configured before calling " +
                "MapZeeKayDaAuth(). Ensure AddZeeKayDaAuth() is called with a valid issuer.");
        }

        // Derive the registration path from the issuer's path component so that a path-bearing
        // issuer (e.g. https://auth.example.com/tenant1) registers at
        // /tenant1/.well-known/openid-configuration rather than at the root, as required by
        // OIDC Discovery 1.0 §4.1 and RFC 9207 §4.
        var issuerUri = new Uri(issuer);
        var issuerPath = issuerUri.AbsolutePath.TrimEnd('/');
        var routePath = issuerPath + WellKnownSuffix;

        endpoints.MapGet(routePath, Handle);
    }

    private static IResult Handle(IDiscoveryDocumentProvider provider, HttpContext context)
    {
        // Cache-Control set directly in the handler per ADR §8 so that the behaviour is
        // co-located with the endpoint and trivially verifiable in tests without a pipeline.
        context.Response.Headers.CacheControl = "public, max-age=86400";

        // Wildcard CORS origin so browser-based OIDC clients can fetch the discovery document.
        context.Response.Headers.AccessControlAllowOrigin = "*";

        return Results.Json(provider.GetDocument());
    }
}
