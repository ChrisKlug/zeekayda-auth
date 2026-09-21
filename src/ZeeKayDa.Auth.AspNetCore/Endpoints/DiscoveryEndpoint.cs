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
internal sealed class DiscoveryEndpoint : IZeeKayDaEndpoint
{
    // Appended to the issuer path to form the discovery document URL per OIDC Discovery §4.1.
    private const string WellKnownSuffix = "/.well-known/openid-configuration";

    // Inserted before the issuer path to form the metadata URL per RFC 8414 §3.1.
    private const string OAuthWellKnownName = "oauth-authorization-server";

    private readonly IOptions<AuthorizationServerOptions> _options;
    private readonly HashSet<string> _allowedOrigins;

    public DiscoveryEndpoint(IOptions<AuthorizationServerOptions> options)
    {
        _options = options;
        // Config values are already validated and canonicalized to lowercase by startup validation.
        _allowedOrigins = new HashSet<string>(
            options.Value.CorsOrigins,
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

        // AllowAnonymous so a host-wide authorization fallback policy cannot turn discovery into a
        // 401 — the document must stay publicly readable per OIDC Discovery 1.0 and RFC 8414 §3.
        // The RFC 8414 document is also served at the appended form, so a proxy forwarding only
        // the issuer's path prefix reaches it exactly as it reaches the OpenID Connect one. On a
        // root issuer the two forms coincide, hence Distinct.
        string[] routes =
        [
            EndpointRouteHelper.GetIssuerPathPrefixedRoute(issuerUri, WellKnownSuffix),
            EndpointRouteHelper.GetWellKnownInsertedRoute(issuerUri, OAuthWellKnownName),
            EndpointRouteHelper.GetIssuerPathPrefixedRoute(issuerUri, "/.well-known/" + OAuthWellKnownName),
        ];

        foreach (var routePath in routes.Distinct(StringComparer.Ordinal))
        {
            endpoints.MapGet(routePath, Handle).RequireIssuerHost(issuerUri).AllowAnonymous();
        }
    }

    /// <remarks>
    /// <para>
    /// <strong>A broken scope repository answers 500 with no body.</strong> This is the only
    /// anonymous endpoint the framework serves, and <c>ValidatedScopeCatalog</c> reports a
    /// contract breach by naming the scope and the audience string it refused. Letting that
    /// exception escape hands those to whatever the host's error handling does with it — on
    /// <c>WebApplication.CreateBuilder</c> in Development, the developer exception page renders
    /// the message to an unauthenticated caller. Every other endpoint already answers a
    /// misconfiguration with a generic error and keeps the detail in the operator's log; this one
    /// now does the same.
    /// </para>
    /// <para>
    /// The cache and CORS headers are applied only once a document exists, so an error is never
    /// served with the cache lifetime a valid document carries.
    /// </para>
    /// </remarks>
    internal async ValueTask<IResult> Handle(
        IDiscoveryDocumentProvider provider,
        ISanitizingLogger<DiscoveryEndpoint> logger,
        HttpContext context)
    {
        OpenIdConfigurationDocument document;
        try
        {
            document = await provider.GetDocumentAsync(context.RequestAborted).ConfigureAwait(false);
        }
        catch (ScopeContractException ex)
        {
            // The codes and messages, not ex.Message. Safe to log only because
            // ScopeContractException is internal, so every failure is this framework's own text;
            // one the repository threw is not caught and never reaches a log line by message.
            logger.LogError(
                "The discovery document could not be built: {Detail}",
                "The scope repository broke its contract: " +
                string.Join("; ", ex.AggregatedFailures.Select(failure => $"[{failure.Code}] {failure.Message}")));

            return Results.StatusCode(StatusCodes.Status500InternalServerError);
        }

        PublicMetadataHeaders.Apply(
            context, _options.Value.DiscoveryDocument.CacheMaxAge, _allowedOrigins);

        return Results.Json(document, ZeeKayDaJsonSerializerContext.Default.OpenIdConfigurationDocument);
    }
}
