using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;
using ZeeKayDa.Auth.StartupVerification;

namespace ZeeKayDa.Auth.AspNetCore.Endpoints;

/// <summary>
/// Warns outside Development when a framework endpoint is reached by no rate limiter. The host's
/// limiter is the control; the framework cannot see one applied before requests reach the
/// application, whether <c>UseRateLimiter()</c> is in the pipeline, or a global limiter passed to
/// <c>UseRateLimiter(RateLimiterOptions)</c> rather than configured as options.
/// </summary>
/// <remarks>
/// A startup filter, not a startup check: the runner starts before a <c>Startup</c>-style host's
/// <c>Configure</c> maps the endpoints, and this runs once the pipeline is built, in either hosting
/// model, before the server starts.
/// </remarks>
internal sealed class EndpointRateLimitingStartupFilter(
    IOptions<RateLimiterOptions> rateLimiterOptions,
    IHostEnvironment environment) : IStartupFilter
{
    internal const string NotRateLimitedCode = "endpoints.not_rate_limited";

    internal const string NotRateLimitedMessage =
        "A ZeeKayDa.Auth endpoint is reached by no rate limiter: it carries no rate-limiting policy, " +
        "and no global limiter covers it. Every authorization request costs the interaction store an " +
        "entry and every provider callback an outbound token request, so their volume is bounded only " +
        "by what the host applies. Attach the host's limiter with " +
        "app.MapZeeKayDaAuth().RequireRateLimiting(\"policy\") and call app.UseRateLimiter(), after " +
        "app.UseRouting() when the host calls that explicitly. A host that limits requests before " +
        "they reach the application can filter this check's log category.";

    internal const string Name = "EndpointRateLimiting";

    /// <inheritdoc/>
    public Action<IApplicationBuilder> Configure(Action<IApplicationBuilder> next) => app =>
    {
        next(app);

        // A host without routing has mapped nothing to check.
        if (app.ApplicationServices.GetService<EndpointDataSource>() is not { } endpoints)
            return;

        var context = new StartupVerificationContext();
        Verify(context, endpoints);
        foreach (var warning in context.Warnings)
            StartupVerificationHostedService.LogWarning(app.ApplicationServices, this, Name, warning);
    };

    /// <summary>Records the warning when any framework endpoint in <paramref name="endpoints"/> is unlimited.</summary>
    internal void Verify(StartupVerificationContext context, EndpointDataSource endpoints)
    {
        if (!environment.IsDevelopment() && endpoints.Endpoints.Where(IsFrameworkEndpoint).Any(endpoint => !IsRateLimited(endpoint)))
            context.AddWarning(NotRateLimitedCode, NotRateLimitedMessage);
    }

    private static bool IsFrameworkEndpoint(Endpoint endpoint) =>
        endpoint.Metadata.GetMetadata<FrameworkEndpointMetadata>() is not null;

    /// <summary>The rate-limiting middleware's own rule: an opt-out wins, else a policy or the global limiter applies.</summary>
    private bool IsRateLimited(Endpoint endpoint) =>
        endpoint.Metadata.GetMetadata<DisableRateLimitingAttribute>() is null
        && (endpoint.Metadata.GetMetadata<EnableRateLimitingAttribute>() is not null
            || rateLimiterOptions.Value.GlobalLimiter is not null);
}
