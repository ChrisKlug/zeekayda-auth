using Microsoft.AspNetCore.Routing;

namespace ZeeKayDa.Auth.AspNetCore.Endpoints;

/// <summary>
/// Represents a single protocol endpoint that can register one or more routes on an
/// <see cref="IEndpointRouteBuilder"/>.
/// </summary>
/// <remarks>
/// Implementations are discovered automatically by <c>MapZeeKayDaAuth()</c> via DI enumeration.
/// Register concrete implementations using <c>TryAddEnumerable</c> in <c>AddZeeKayDaAuth()</c>
/// to guarantee idempotent registration even if the method is called more than once.
/// </remarks>
internal interface IZeeKayDaEndpoint
{
    /// <summary>Registers this endpoint's routes on the supplied <paramref name="endpoints"/>.</summary>
    /// <param name="endpoints">The route builder to register against.</param>
    void Map(IEndpointRouteBuilder endpoints);
}
