using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.Options;
using ZeeKayDa.Auth;

namespace ZeeKayDa.Auth.AspNetCore.Endpoints;

internal static class EndpointRouteHelper
{
    public static Uri GetIssuerUri(IOptions<AuthorizationServerOptions> options)
    {
        var issuer = options.Value.Issuer;

        if (string.IsNullOrWhiteSpace(issuer))
        {
            throw new InvalidOperationException(
                "AuthorizationServerOptions.Issuer must be configured before calling " +
                "MapZeeKayDaAuth(). Ensure AddZeeKayDaAuth() is called with a valid issuer.");
        }

        return new Uri(issuer);
    }

    public static string GetIssuerPathPrefixedRoute(Uri issuerUri, string suffix)
        => issuerUri.AbsolutePath.TrimEnd('/') + suffix;

    public static Uri GetPublishedEndpointUri(Uri issuerUri, string? endpointOverride, string relativePath)
    {
        if (endpointOverride is not null)
        {
            return new Uri(endpointOverride);
        }

        var baseUri = issuerUri.AbsolutePath.EndsWith('/')
            ? issuerUri
            : new Uri(issuerUri.AbsoluteUri + "/");

        return new Uri(baseUri, relativePath);
    }

    public static string GetRoutePath(Uri endpointUri)
        => endpointUri.AbsolutePath;

    public static RouteHandlerBuilder RequireIssuerHost(this RouteHandlerBuilder builder, Uri endpointUri)
        => builder.RequireHost(endpointUri.Authority);
}
