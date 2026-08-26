namespace ZeeKayDa.Auth.AspNetCore.Endpoints;

/// <summary>
/// Builds the <c>Cache-Control</c> value the public metadata endpoints (discovery, JWKS) share.
/// </summary>
internal static class CacheControlHeader
{
    /// <summary>
    /// Returns <c>public, max-age={seconds}, must-revalidate</c> for a positive
    /// <paramref name="maxAge"/> (truncated to whole seconds), or <c>no-store</c> at zero.
    /// </summary>
    /// <param name="maxAge">The configured, startup-validated non-negative max-age.</param>
    /// <remarks>
    /// <c>must-revalidate</c> (not <c>proxy-revalidate</c>) so browser caches, not just CDN/proxy
    /// caches, are required to revalidate after the TTL expires.
    /// </remarks>
    public static string For(TimeSpan maxAge)
        => maxAge > TimeSpan.Zero
            ? $"public, max-age={(long)maxAge.TotalSeconds}, must-revalidate"
            : "no-store";
}
