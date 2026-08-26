namespace ZeeKayDa.Auth.AspNetCore.Endpoints;

/// <summary>
/// Builds the <c>Cache-Control</c> value the public metadata endpoints (discovery, JWKS) share.
/// </summary>
internal static class CacheControlHeader
{
    /// <summary>
    /// Returns <c>public, max-age={seconds}, must-revalidate</c> for a <paramref name="maxAge"/>
    /// of at least one second (truncated to whole seconds), or <c>no-store</c> below that — a
    /// sub-second TTL truncating to a cacheable <c>max-age=0</c> would contradict the documented
    /// "zero disables caching" contract.
    /// </summary>
    /// <param name="maxAge">The configured, startup-validated non-negative max-age.</param>
    /// <remarks>
    /// <c>must-revalidate</c> (not <c>proxy-revalidate</c>) so browser caches, not just CDN/proxy
    /// caches, are required to revalidate after the TTL expires.
    /// </remarks>
    public static string For(TimeSpan maxAge)
        => maxAge >= TimeSpan.FromSeconds(1)
            ? $"public, max-age={(long)maxAge.TotalSeconds}, must-revalidate"
            : "no-store";
}
