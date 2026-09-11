using Microsoft.AspNetCore.Http;
using Microsoft.Net.Http.Headers;

namespace ZeeKayDa.Auth.AspNetCore.Interaction;

/// <summary>
/// The response headers every host page that takes a decision renders under: framed by nobody
/// and cached by nothing.
/// </summary>
/// <remarks>
/// The consent page takes a one-click decision, and the page a provider sign-in lands on shows
/// the provider's identity and takes one too. An attacker who can frame either can steer that
/// click. No such page can render without the read that stamps this, which is what makes it a
/// guarantee rather than guidance. The frame-ancestors policy is appended, so a policy the host
/// set of its own still applies alongside it.
/// </remarks>
internal static class RenderedPage
{
    public static void Protect(HttpResponse response)
    {
        ArgumentNullException.ThrowIfNull(response);

        var headers = response.Headers;
        headers.CacheControl = "no-store";
        headers.Append(HeaderNames.ContentSecurityPolicy, "frame-ancestors 'none'");
        headers.XFrameOptions = "DENY";
    }
}
