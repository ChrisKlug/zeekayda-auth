using Microsoft.AspNetCore.Http;

namespace ZeeKayDa.Auth.AspNetCore.Endpoints;

/// <summary>
/// Emits the CORS response headers the public metadata endpoints (discovery, JWKS) share.
/// </summary>
internal static class CorsHeaders
{
    /// <summary>
    /// Emits <c>Access-Control-Allow-Origin: *</c> when <paramref name="allowedOrigins"/> is empty;
    /// otherwise emits <c>Vary: Origin</c> and, when the request's <c>Origin</c> matches an
    /// allowlist entry, that entry in <c>Access-Control-Allow-Origin</c>.
    /// </summary>
    /// <param name="context">The request being answered.</param>
    /// <param name="allowedOrigins">
    /// The startup-validated, canonicalized allowlist, in a case-insensitive set.
    /// </param>
    public static void Apply(HttpContext context, HashSet<string> allowedOrigins)
    {
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
