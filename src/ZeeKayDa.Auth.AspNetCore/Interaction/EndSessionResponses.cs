using System.Text.Encodings.Web;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Options;
using ZeeKayDa.Auth.Clients;

namespace ZeeKayDa.Auth.AspNetCore.Interaction;

/// <summary>
/// How a sign-out ends, and the pages the framework renders for a host that built none of its
/// own: the confirmation, the signed-out page, and the two refusals.
/// </summary>
/// <remarks>
/// A redirect back to a client goes only to a post-logout redirect URI matched against that
/// client's registration, and carries its <c>state</c> without passing through a logger. The pages
/// are framework text; the one value rendered, a client's display name, comes from its
/// registration and is HTML-encoded.
/// </remarks>
internal sealed class EndSessionResponses
{
    private readonly IOptions<AuthorizationServerOptions> _options;

    public EndSessionResponses(IOptions<AuthorizationServerOptions> options)
    {
        ArgumentNullException.ThrowIfNull(options);

        _options = options;
    }

    /// <summary>
    /// Ends the SSO session and every interaction this browser has in flight, then answers: at the
    /// client's post-logout redirect URI, at the host's signed-out page, or with the framework's
    /// own.
    /// </summary>
    /// <param name="context">The request signing out.</param>
    /// <param name="redirect">Where to send the user back to the client, or <see langword="null"/>.</param>
    public async Task<IResult> SignOutAsync(HttpContext context, PostLogoutRedirect? redirect)
    {
        ArgumentNullException.ThrowIfNull(context);

        // Only a browser that presented the session cookie gets one deleted. A cross-site form
        // post carries no SameSite=Lax cookie, so answering it with a deletion would end the
        // session without the question §2 requires — and would end interactions belonging to a
        // browser that never signed in. A cookie that is present but unreadable is still cleared.
        if (context.Request.Cookies.ContainsKey(ZeeKayDaCookies.Session))
        {
            // The cookie handler deletes the session cookie with the attributes it was issued
            // with, which is what makes a browser actually drop it.
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
        _options.Value.EndSessionEndpoint.SignedOutPath is { } signedOutPath
            ? Results.Redirect(signedOutPath)
            : Page(StatusCodes.Status200OK, "Signed out", "<h1>You have been signed out.</h1>");

    /// <summary>
    /// The framework's confirmation page. Its form has no <c>action</c>, so it posts back to the
    /// URL it was rendered at, <c>zkd_i</c> included.
    /// </summary>
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

        return Results.Content(html, "text/html; charset=utf-8", statusCode: statusCode);
    }
}
