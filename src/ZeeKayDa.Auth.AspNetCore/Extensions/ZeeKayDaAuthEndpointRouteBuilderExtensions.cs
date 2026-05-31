using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
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

        foreach (var endpoint in endpoints.ServiceProvider.GetServices<IZeeKayDaEndpoint>())
        {
            endpoint.Map(endpoints);
        }

        return endpoints;
    }
}
