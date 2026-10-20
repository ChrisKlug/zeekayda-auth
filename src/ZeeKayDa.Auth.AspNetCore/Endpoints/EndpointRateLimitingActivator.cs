using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;
using ZeeKayDa.Auth.StartupVerification;

namespace ZeeKayDa.Auth.AspNetCore.Endpoints;

/// <summary>
/// Warns outside Development when a framework endpoint is reached by no rate limiter. The host's
/// limiter is the control; the framework cannot see one applied before requests reach the
/// application, nor whether <c>UseRateLimiter()</c> is in the pipeline.
/// </summary>
/// <remarks>
/// An activator, not a verifier: the endpoints carry the host's conventions, and the limiter
/// options its configuration.
/// </remarks>
internal sealed class EndpointRateLimitingActivator(
    MappedFrameworkEndpoints endpoints,
    IOptions<RateLimiterOptions> rateLimiterOptions,
    IHostEnvironment environment) : IStartupActivator
{
    internal const string NotRateLimitedCode = "endpoints.not_rate_limited";

    internal const string NotRateLimitedMessage =
        "A ZeeKayDa.Auth endpoint is reached by no rate limiter: it carries no rate-limiting policy, " +
        "and no global limiter covers it. Every authorization request costs the interaction store an " +
        "entry and every provider callback an outbound token request, so their volume is bounded only " +
        "by what the host applies. Attach the host's limiter with " +
        "app.MapZeeKayDaAuth().RequireRateLimiting(\"policy\") and call app.UseRateLimiter(). A host " +
        "that limits requests before they reach the application can filter this check's log category.";

    /// <inheritdoc/>
    public string Name => "EndpointRateLimiting";

    /// <inheritdoc/>
    public Task VerifyAsync(StartupVerificationContext context, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);

        if (!environment.IsDevelopment() && endpoints.Endpoints.Any(endpoint => !IsRateLimited(endpoint)))
            context.AddWarning(NotRateLimitedCode, NotRateLimitedMessage);

        return Task.CompletedTask;
    }

    /// <summary>The rate-limiting middleware's own rule: an opt-out wins, else a policy or the global limiter applies.</summary>
    private bool IsRateLimited(Endpoint endpoint) =>
        endpoint.Metadata.GetMetadata<DisableRateLimitingAttribute>() is null
        && (endpoint.Metadata.GetMetadata<EnableRateLimitingAttribute>() is not null
            || rateLimiterOptions.Value.GlobalLimiter is not null);
}
