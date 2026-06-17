using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using ZeeKayDa.Auth;
using ZeeKayDa.Auth.AspNetCore;
using ZeeKayDa.Auth.AspNetCore.Endpoints;

namespace Microsoft.AspNetCore.Builder;

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

        // Force eager options evaluation so Map-time failures match ValidateOnStart
        // (OptionsValidationException with the validator's exact messages).
        var options = endpoints.ServiceProvider
            .GetRequiredService<IOptions<AuthorizationServerOptions>>()
            .Value;

        // Precompute security header values once at map time — they are fixed for the lifetime
        // of the application and do not need to be re-evaluated per request.
        var securityHeaders = options.SecurityHeaders;
        var referrerPolicyValue = SecurityHeaderValues.ToHeaderValue(securityHeaders.ReferrerPolicy);
        var corpValue = SecurityHeaderValues.ToHeaderValue(securityHeaders.CrossOriginResourcePolicy);
        var noSniff = securityHeaders.ContentTypeOptionsNoSniff;
        var allowInsecureIssuer = options.AllowInsecureIssuer;

        // All ZeeKayDa.Auth endpoints are grouped so that the security-headers filter applies
        // only to protocol endpoints and not to the host application's own routes.
        var group = endpoints.MapGroup("");

        group.AddEndpointFilter(async (context, next) =>
        {
            if (context.HttpContext.Request.IsHttps ||
                (allowInsecureIssuer && LoopbackHelper.IsLoopbackAddress(context.HttpContext.Connection.RemoteIpAddress)))
            {
                return await next(context);
            }

            return Results.Problem(
                statusCode: StatusCodes.Status421MisdirectedRequest,
                title: "HTTPS required",
                detail: "ZeeKayDa.Auth endpoints require HTTPS for non-loopback requests. " +
                        "Configure TLS, or use AllowInsecureIssuer only for loopback development.");
        });

        group.AddEndpointFilter(async (context, next) =>
        {
            if (noSniff)
                context.HttpContext.Response.Headers["X-Content-Type-Options"] = "nosniff";

            context.HttpContext.Response.Headers["Referrer-Policy"] = referrerPolicyValue;
            context.HttpContext.Response.Headers["Cross-Origin-Resource-Policy"] = corpValue;

            if (allowInsecureIssuer)
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
