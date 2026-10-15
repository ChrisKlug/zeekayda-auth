using Microsoft.AspNetCore.Http;
using Microsoft.Net.Http.Headers;

namespace ZeeKayDa.Auth.AspNetCore.Interaction;

/// <summary>
/// The headers every framework page, and every host page that takes a decision, renders under:
/// framed by nobody and cached by nothing.
/// </summary>
/// <remarks>
/// A framed one-click decision can be steered by the framer. The frame-ancestors policy is
/// appended, so a host's own policy still applies.
/// </remarks>
internal static class RenderedPage
{
    private const string FrameAncestorsNone = "frame-ancestors 'none'";

    public static void Protect(HttpResponse response)
    {
        ArgumentNullException.ThrowIfNull(response);

        var headers = response.Headers;
        headers.CacheControl = "no-store";
        headers.XFrameOptions = "DENY";

        // A framework page rendered after a host page's read must not append it twice.
        if (!headers.ContentSecurityPolicy.Contains(FrameAncestorsNone, StringComparer.Ordinal))
            headers.Append(HeaderNames.ContentSecurityPolicy, FrameAncestorsNone);
    }

    /// <summary>An HTML page the framework renders itself, stamped as it is written.</summary>
    public static IResult Html(int statusCode, string html) => new ProtectedHtml(statusCode, html);

    private sealed class ProtectedHtml(int statusCode, string html) : IResult
    {
        public Task ExecuteAsync(HttpContext httpContext)
        {
            ArgumentNullException.ThrowIfNull(httpContext);

            Protect(httpContext.Response);

            return Results.Content(html, "text/html; charset=utf-8", statusCode: statusCode)
                .ExecuteAsync(httpContext);
        }
    }
}
