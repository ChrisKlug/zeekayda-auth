using Microsoft.AspNetCore.Http;

namespace ZeeKayDa.Auth.AspNetCore.Endpoints;

/// <summary>
/// Writes the response headers every public metadata endpoint (discovery, JWKS) carries: the
/// <c>Cache-Control</c> directive and the CORS headers. One call, so an endpoint cannot apply one
/// half of the treatment and forget the other.
/// </summary>
internal static class PublicMetadataHeaders
{
    /// <summary>
    /// Applies the shared metadata-response headers to <paramref name="context"/>'s response.
    /// </summary>
    /// <param name="context">The request being answered.</param>
    /// <param name="cacheMaxAge">
    /// The configured, startup-validated non-negative cache TTL. At one second or more the
    /// response carries <c>public, max-age={seconds}, must-revalidate</c> (truncated to whole
    /// seconds); below that, <c>no-store</c> — a sub-second TTL truncating to a cacheable
    /// <c>max-age=0</c> would contradict the documented "zero disables caching" contract.
    /// </param>
    /// <param name="allowedOrigins">
    /// The startup-validated, canonicalized CORS allowlist, in a case-insensitive set. Empty
    /// emits <c>Access-Control-Allow-Origin: *</c>; non-empty emits <c>Vary: Origin</c> and, when
    /// the request's <c>Origin</c> matches an allowlist entry, that entry in
    /// <c>Access-Control-Allow-Origin</c>.
    /// </param>
    /// <remarks>
    /// <c>must-revalidate</c> (not <c>proxy-revalidate</c>) so browser caches, not just CDN/proxy
    /// caches, are required to revalidate after the TTL expires.
    /// </remarks>
    public static void Apply(HttpContext context, TimeSpan cacheMaxAge, HashSet<string> allowedOrigins)
    {
        context.Response.Headers.CacheControl = cacheMaxAge >= TimeSpan.FromSeconds(1)
            ? $"public, max-age={(long)cacheMaxAge.TotalSeconds}, must-revalidate"
            : "no-store";

        if (allowedOrigins.Count == 0)
        {
            context.Response.Headers.AccessControlAllowOrigin = "*";
            return;
        }

        // Vary: Origin so caches never serve a wildcard-cached response to an
        // allowlisted-origin request or vice-versa.
        context.Response.Headers.Append("Vary", "Origin");

        var requestOrigin = context.Request.Headers.Origin.ToString();
        if (!string.IsNullOrEmpty(requestOrigin) &&
            allowedOrigins.TryGetValue(requestOrigin, out var allowedOrigin))
        {
            // Emit the matching allowlist entry, NEVER the raw incoming header value.
            context.Response.Headers.AccessControlAllowOrigin = allowedOrigin;
        }
    }
}
