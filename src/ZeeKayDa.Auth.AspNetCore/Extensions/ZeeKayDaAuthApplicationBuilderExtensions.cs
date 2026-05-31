using Microsoft.AspNetCore.Builder;

namespace ZeeKayDa.Auth.AspNetCore.Extensions;

/// <summary>
/// Extension methods for <see cref="IApplicationBuilder"/> to register ZeeKayDa.Auth protocol
/// endpoints without manually calling <c>UseEndpoints(...)</c>.
/// </summary>
public static class ZeeKayDaAuthApplicationBuilderExtensions
{
    /// <summary>
    /// Registers all ZeeKayDa.Auth protocol endpoints on the supplied application builder.
    /// </summary>
    /// <param name="app">The application builder to register endpoints on.</param>
    /// <returns>The <paramref name="app"/> builder so that calls can be chained.</returns>
    /// <exception cref="ArgumentNullException">
    /// Thrown when <paramref name="app"/> is <see langword="null"/>.
    /// </exception>
    /// <remarks>
    /// Call <c>app.UseRouting()</c> before invoking this method. Internally it delegates to
    /// <c>UseEndpoints(endpoints =&gt; endpoints.MapZeeKayDaAuth())</c>.
    /// </remarks>
    public static IApplicationBuilder MapZeeKayDaAuth(this IApplicationBuilder app)
    {
        ArgumentNullException.ThrowIfNull(app);

        app.UseEndpoints(endpoints => endpoints.MapZeeKayDaAuth());

        return app;
    }
}
