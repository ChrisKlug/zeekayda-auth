using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using ZeeKayDa.Auth;
using ZeeKayDa.Auth.AspNetCore;
using ZeeKayDa.Auth.AspNetCore.Endpoints;
using ZeeKayDa.Auth.StartupVerification;

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
    /// A builder for conventions on the framework's endpoints only, such as the host's rate limiter:
    /// <c>app.MapZeeKayDaAuth().RequireRateLimiting("policy")</c>.
    /// </returns>
    /// <exception cref="ArgumentNullException">
    /// Thrown when <paramref name="endpoints"/> is <see langword="null"/>.
    /// </exception>
    /// <remarks>
    /// <para>
    /// Endpoint implementations are discovered automatically from DI via
    /// <see cref="IZeeKayDaEndpoint"/>. Call <c>services.AddZeeKayDaAuth()</c> during service
    /// registration to ensure all required services are available.
    /// </para>
    /// <para>
    /// The framework applies no rate limiting of its own; the host's limiter is the control. Outside
    /// Development, startup warns when an endpoint is reached by neither a policy attached here nor a
    /// global limiter.
    /// </para>
    /// </remarks>
    public static IEndpointConventionBuilder MapZeeKayDaAuth(this IEndpointRouteBuilder endpoints)
    {
        ArgumentNullException.ThrowIfNull(endpoints);

        // Every options type, so the first error lists all their failures.
        ValidatedOptionsCheck.ThrowIfAnyInvalid(endpoints.ServiceProvider);

        var options = endpoints.ServiceProvider
            .GetRequiredService<IOptions<AuthorizationServerOptions>>()
            .Value;

        var securityHeaders = options.SecurityHeaders;
        var referrerPolicyValue = SecurityHeaderValues.ToHeaderValue(securityHeaders.ReferrerPolicy);
        var corpValue = SecurityHeaderValues.ToHeaderValue(securityHeaders.CrossOriginResourcePolicy);
        var noSniff = securityHeaders.ContentTypeOptionsNoSniff;
        var allowHttpLoopbackIssuer = options.Development.AllowHttpLoopbackIssuer;

        // The filters below apply to the framework's endpoints, never the host's routes.
        var group = endpoints.MapGroup("");

        // MapGroup added the group's data source last.
        endpoints.ServiceProvider.GetRequiredService<MappedFrameworkEndpoints>().Add(endpoints.DataSources.Last());

        // A URL path is case-sensitive (RFC 3986 §6.2.2.1); routing literals are not.
        group.WithMetadata(ExactPathMetadata.Instance);

        group.AddEndpointFilter(async (context, next) =>
        {
            if (context.HttpContext.Request.IsHttps ||
                (allowHttpLoopbackIssuer && LoopbackHelper.IsLoopbackAddress(context.HttpContext.Connection.RemoteIpAddress)))
            {
                return await next(context);
            }

            return Results.Problem(
                statusCode: StatusCodes.Status421MisdirectedRequest,
                title: "HTTPS required",
                detail: "ZeeKayDa.Auth endpoints require HTTPS for non-loopback requests. " +
                        "Configure TLS. Behind a TLS-terminating reverse proxy, call UseForwardedHeaders() with " +
                        "ForwardedHeaders.XForwardedProto enabled and KnownProxies or KnownIPNetworks scoped to the proxy, " +
                        "so the original scheme is restored. " +
                        "Use Development.AllowHttpLoopbackIssuer only for loopback development.");
        });

        group.AddEndpointFilter(async (context, next) =>
        {
            if (noSniff)
                context.HttpContext.Response.Headers["X-Content-Type-Options"] = "nosniff";

            context.HttpContext.Response.Headers["Referrer-Policy"] = referrerPolicyValue;
            context.HttpContext.Response.Headers["Cross-Origin-Resource-Policy"] = corpValue;

            if (allowHttpLoopbackIssuer)
                context.HttpContext.Response.Headers["X-ZeeKayDa-Insecure-Issuer"] = "true";

            return await next(context);
        });

        foreach (var endpoint in endpoints.ServiceProvider.GetServices<IZeeKayDaEndpoint>())
        {
            endpoint.Map(group);
        }

        return group;
    }
}
