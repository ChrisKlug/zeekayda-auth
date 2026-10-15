using System.Text.Encodings.Web;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Options;
using ZeeKayDa.Auth.Clients;

namespace ZeeKayDa.Auth.AspNetCore.Interaction;

/// <summary>
/// How a sign-out ends, and the framework's own pages for a host that built none. A redirect goes
/// only to a registered post-logout redirect URI, unlogged.
/// </summary>
internal sealed class EndSessionResponses(IOptions<AuthorizationServerOptions> options)
{
    /// <summary>Ends the SSO session and this browser's interactions, then answers at the client or a signed-out page.</summary>
    /// <param name="context">The request signing out.</param>
    /// <param name="redirect">Where to send the user back to the client, or <see langword="null"/>.</param>
    public async Task<IResult> SignOutAsync(HttpContext context, PostLogoutRedirect? redirect)
    {
        ArgumentNullException.ThrowIfNull(context);

        // A cross-site post carries no Lax session cookie, and must not end the session unasked (§2).
        if (context.Request.Cookies.ContainsKey(ZeeKayDaCookies.Session))
        {
            // Through the handler, so the deletion carries the attributes the browser needs to drop it.
            await context.SignOutAsync(ZeeKayDaCookies.Session).ConfigureAwait(false);
            InteractionBindingCookie.DeleteAll(context);
        }

        if (redirect is not null)
        {
            return new UnloggedRedirect(redirect.State is null
                ? redirect.Uri
                : QueryHelpers.AddQueryString(redirect.Uri, "state", redirect.State));
        }

        return SignedOut();
    }

    /// <summary>The host's signed-out page, or the framework's own. Signs nothing out.</summary>
    public IResult SignedOut() =>
        options.Value.EndSessionEndpoint.SignedOutPath is { } signedOutPath
            ? Results.Redirect(signedOutPath)
            : Page(StatusCodes.Status200OK, "Signed out", "<h1>You have been signed out.</h1>");

    /// <summary>The framework's confirmation page, whose action-less form posts back with <c>zkd_i</c>.</summary>
    public static IResult Confirmation(ClientInformation? client)
    {
        var heading = client?.DisplayName is { } name
            ? $"Sign out of {HtmlEncoder.Default.Encode(name)}?"
            : "Sign out?";

        return Page(
            StatusCodes.Status200OK,
            "Sign out",
            $"<h1>{heading}</h1><form method=\"post\"><button type=\"submit\">Sign out</button></form>");
    }

    /// <summary>A confirmation that names no sign-out this browser is carrying.</summary>
    public static IResult NothingToConfirm() => Page(
        StatusCodes.Status400BadRequest,
        "Sign-out request error",
        "<h1>There is no sign-out to confirm.</h1>" +
        "<p>It expired, was already completed, was started in another browser, or the session it " +
        "was for has since ended. Return to the application and sign out again.</p>");

    /// <summary>The interaction store could not be reached, so the user could not be asked.</summary>
    public static IResult Unavailable() => Page(
        StatusCodes.Status500InternalServerError,
        "Sign-out unavailable",
        "<h1>Signing out could not be completed.</h1><p>Try again in a moment.</p>");

    private static IResult Page(int statusCode, string title, string body)
    {
        var html =
            "<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"utf-8\">" +
            $"<title>{title}</title></head><body>{body}</body></html>";

        return RenderedPage.Html(statusCode, html);
    }
}
