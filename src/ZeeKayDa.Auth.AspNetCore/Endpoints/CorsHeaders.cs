using Microsoft.AspNetCore.Http;

namespace ZeeKayDa.Auth.AspNetCore.Endpoints;

/// <summary>
/// Writes the CORS response headers every endpoint a browser script may call shares: discovery,
/// JWKS and userinfo, all governed by one allowlist.
/// </summary>
/// <remarks>
/// No <c>Access-Control-Allow-Credentials</c> is ever written, which is what keeps the wildcard
/// safe: none of these endpoints authenticates with a cookie, so a request carrying ambient
/// credentials is never the one being answered.
/// </remarks>
internal static class CorsHeaders
{
    /// <summary>
    /// Applies the allowlist to <paramref name="context"/>'s response. An empty allowlist emits
    /// <c>Access-Control-Allow-Origin: *</c>; a non-empty one emits <c>Vary: Origin</c> and, when
    /// the request's <c>Origin</c> matches an entry, that entry — never the raw header value.
    /// </summary>
    /// <param name="context">The request being answered.</param>
    /// <param name="allowedOrigins">
    /// The startup-validated, canonicalized allowlist, in a case-insensitive set.
    /// </param>
    public static void ApplyOrigin(HttpContext context, HashSet<string> allowedOrigins)
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

    /// <summary>
    /// Answers a CORS preflight for an endpoint reached with a bearer token: the allowlist's
    /// origin decision, plus the methods and request headers a browser must be told are allowed
    /// before it will send the real request.
    /// </summary>
    /// <param name="context">The preflight request being answered.</param>
    /// <param name="allowedOrigins">The startup-validated, canonicalized allowlist.</param>
    /// <param name="methods">The <c>Access-Control-Allow-Methods</c> value.</param>
    /// <param name="headers">The <c>Access-Control-Allow-Headers</c> value.</param>
    /// <param name="maxAge">How long a browser may cache this preflight, in seconds.</param>
    public static void ApplyPreflight(
        HttpContext context, HashSet<string> allowedOrigins, string methods, string headers, int maxAge)
    {
        ApplyOrigin(context, allowedOrigins);

        context.Response.Headers.AccessControlAllowMethods = methods;
        context.Response.Headers.AccessControlAllowHeaders = headers;
        context.Response.Headers.AccessControlMaxAge = maxAge.ToString(System.Globalization.CultureInfo.InvariantCulture);
    }
}
