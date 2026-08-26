using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.Options;
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
    private readonly HashSet<string> _allowedOrigins;

    public DiscoveryEndpoint(IOptions<AuthorizationServerOptions> options)
    {
        _options = options;
        // Config values are already validated and canonicalized to lowercase by startup validation.
        _allowedOrigins = new HashSet<string>(
            options.Value.DiscoveryDocument.CorsOrigins,
            StringComparer.OrdinalIgnoreCase);
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

        // AllowAnonymous so a host-wide authorization fallback policy cannot turn discovery into a
        // 401 — the document must stay publicly readable per OIDC Discovery 1.0.
        endpoints.MapGet(routePath, Handle).RequireIssuerHost(issuerUri).AllowAnonymous();
    }

    private async ValueTask<IResult> Handle(
        IDiscoveryDocumentProvider provider,
        HttpContext context)
    {
        PublicMetadataHeaders.Apply(
            context, _options.Value.DiscoveryDocument.CacheMaxAge, _allowedOrigins);

        var document = await provider.GetDocumentAsync(context.RequestAborted).ConfigureAwait(false);
        return Results.Json(document, ZeeKayDaJsonSerializerContext.Default.OpenIdConfigurationDocument);
    }
}
