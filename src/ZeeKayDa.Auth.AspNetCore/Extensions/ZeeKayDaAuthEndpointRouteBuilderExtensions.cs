using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using ZeeKayDa.Auth;
using ZeeKayDa.Auth.AspNetCore.Endpoints;

namespace ZeeKayDa.Auth.AspNetCore.Extensions;

/// <summary>
/// Extension methods for <see cref="IEndpointRouteBuilder"/> to register ZeeKayDa.Auth protocol
/// endpoints.
/// </summary>
public static class ZeeKayDaAuthEndpointRouteBuilderExtensions
{
    /// <summary>
    /// Registers all ZeeKayDa.Auth protocol endpoints (OIDC discovery, authorization, token, JWKS,
    /// etc.) on the supplied <paramref name="endpoints"/> route builder.
    /// </summary>
    /// <param name="endpoints">The route builder to register endpoints on.</param>
    /// <returns>
    /// The <paramref name="endpoints"/> builder so that calls can be chained.
    /// </returns>
    /// <exception cref="ArgumentNullException">
    /// Thrown when <paramref name="endpoints"/> is <see langword="null"/>.
    /// </exception>
    /// <remarks>
    /// Endpoint implementations are discovered automatically from DI via
    /// <see cref="IZeeKayDaEndpoint"/>. Call <c>services.AddZeeKayDaAuth()</c> during service
    /// registration to ensure all required services are available.
    /// </remarks>
    public static IEndpointRouteBuilder MapZeeKayDaAuth(this IEndpointRouteBuilder endpoints)
    {
        ArgumentNullException.ThrowIfNull(endpoints);

        // All ZeeKayDa.Auth endpoints are grouped so that the security-headers filter applies
        // only to protocol endpoints and not to the host application's own routes.
        var group = endpoints.MapGroup("");

        group.AddEndpointFilter(async (context, next) =>
        {
            var opts = context.HttpContext.RequestServices
                .GetRequiredService<IOptions<AuthorizationServerOptions>>().Value;
            var securityHeaders = opts.SecurityHeaders;

            if (securityHeaders.ContentTypeOptionsNoSniff)
                context.HttpContext.Response.Headers["X-Content-Type-Options"] = "nosniff";

            context.HttpContext.Response.Headers["Referrer-Policy"] =
                SecurityHeaderValues.ToHeaderValue(securityHeaders.ReferrerPolicy);

            context.HttpContext.Response.Headers["Cross-Origin-Resource-Policy"] =
                SecurityHeaderValues.ToHeaderValue(securityHeaders.CrossOriginResourcePolicy);

            if (opts.AllowInsecureIssuer)
                context.HttpContext.Response.Headers["X-ZeeKayDa-Insecure-Issuer"] = "true";

            return await next(context);
        });

        foreach (var endpoint in endpoints.ServiceProvider.GetServices<IZeeKayDaEndpoint>())
        {
            endpoint.Map(group);
        }

        return endpoints;
    }
}
