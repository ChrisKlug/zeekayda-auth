using Microsoft.AspNetCore.Http;
using Microsoft.Net.Http.Headers;

namespace ZeeKayDa.Auth.AspNetCore.Interaction;

/// <summary>
/// The response headers every page the framework renders, and every host page that takes a
/// decision, renders under: framed by nobody and cached by nothing.
/// </summary>
/// <remarks>
/// The consent page takes a one-click decision, and the page a provider sign-in lands on shows
/// the provider's identity and takes one too. An attacker who can frame either can steer that
/// click. No such page can render without the read that stamps this, which is what makes it a
/// guarantee rather than guidance. The framework's own pages — the sign-out confirmation, the
/// signed-out page, the error and refusal pages — go through <see cref="Html"/> for the same
/// reason: one of them takes a click today, and a page that is framed can acquire a button later.
/// The frame-ancestors policy is appended, so a policy the host set of its own still applies
/// alongside it.
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

        // A framework page rendered after a host page's read would otherwise append the policy a
        // second time.
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
