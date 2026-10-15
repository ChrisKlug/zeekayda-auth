using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using ZeeKayDa.Auth.Discovery;
using ZeeKayDa.Auth.Logging;
using ZeeKayDa.Auth.Scopes;

namespace ZeeKayDa.Auth.AspNetCore.Endpoints;

/// <summary>
/// Registers the discovery document at both of its addresses: OpenID Connect Discovery 1.0
/// (<c>GET /.well-known/openid-configuration</c>, appended to the issuer path) and RFC 8414
/// Authorization Server Metadata (<c>GET /.well-known/oauth-authorization-server</c>, inserted
/// before the issuer path).
/// </summary>
/// <remarks>
/// Both serve the same document. RFC 8414 §7.1.2 registers the OpenID Connect Discovery fields as
/// OAuth metadata, so the OpenID Connect superset is valid at the OAuth address too.
/// </remarks>
internal sealed class DiscoveryEndpoint(IOptions<AuthorizationServerOptions> options, CorsAllowlist allowedOrigins) : IZeeKayDaEndpoint
{
    // Appended to the issuer path to form the discovery document URL per OIDC Discovery §4.1.
    private const string WellKnownSuffix = "/.well-known/openid-configuration";

    // Inserted before the issuer path to form the metadata URL per RFC 8414 §3.1.
    private const string OAuthWellKnownName = "oauth-authorization-server";

    /// <inheritdoc/>
    public void Map(IEndpointRouteBuilder endpoints)
    {
        var issuerUri = EndpointRouteHelper.GetIssuerUri(options);

        // RFC 8414 is also served at the appended form, for a proxy forwarding only the issuer's
        // path prefix. On a root issuer the forms coincide.
        string[] routes =
        [
            EndpointRouteHelper.GetIssuerPathPrefixedRoute(issuerUri, WellKnownSuffix),
            EndpointRouteHelper.GetWellKnownInsertedRoute(issuerUri, OAuthWellKnownName),
            EndpointRouteHelper.GetIssuerPathPrefixedRoute(issuerUri, "/.well-known/" + OAuthWellKnownName),
        ];

        foreach (var routePath in routes.Distinct(StringComparer.Ordinal))
        {
            endpoints.MapGet(routePath, Handle).RequireIssuerHost(issuerUri).ExemptFromHostAuthorization();
        }
    }

    internal async ValueTask<IResult> Handle(
        IDiscoveryDocumentProvider provider,
        SanitizingLogger<DiscoveryEndpoint> logger,
        HttpContext context)
    {
        if (await TryBuildDocumentAsync(provider, logger, context).ConfigureAwait(false) is not { } document)
            return Results.StatusCode(StatusCodes.Status500InternalServerError);

        // Only once a document exists, so an error never carries a valid document's cache lifetime.
        PublicMetadataHeaders.Apply(
            context, options.Value.DiscoveryDocument.CacheMaxAge, allowedOrigins);

        return Results.Json(document, ZeeKayDaJsonSerializerContext.Default.OpenIdConfigurationDocument);
    }

    /// <summary>
    /// The document, or <see langword="null"/> with the failure logged. A failure never escapes: this
    /// endpoint is anonymous, and a Development exception page would render it to the caller.
    /// </summary>
    private static async ValueTask<OpenIdConfigurationDocument?> TryBuildDocumentAsync(
        IDiscoveryDocumentProvider provider,
        SanitizingLogger<DiscoveryEndpoint> logger,
        HttpContext context)
    {
        try
        {
            return await provider.GetDocumentAsync(context.RequestAborted).ConfigureAwait(false);
        }
        catch (ScopeContractException ex)
        {
            logger.LogError(
                "The discovery document could not be built: {Detail}",
                "The scope repository broke its contract: " + ex.DescribeFailures());

            return null;
        }
        catch (Exception ex) when (ex is not OperationCanceledException || !context.RequestAborted.IsCancellationRequested)
        {
            // The type only: a provider's message can carry a connection string, which redaction by key name misses.
            logger.LogError(
                "The discovery document could not be built: the provider threw {ExceptionType}.",
                ex.GetType().FullName);

            return null;
        }
    }
}
