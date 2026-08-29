using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.WebUtilities;

namespace ZeeKayDa.Auth.AspNetCore.Interaction;

/// <summary>
/// The handoff between the framework and a host-rendered interaction page: the query parameter
/// naming the interaction, written onto every redirect the framework makes to a host page, and
/// read back when that page calls a terminal interaction method.
/// </summary>
/// <remarks>
/// <para>
/// Consumption is bound by this parameter, and that binding is the point. Without it, a sign-in
/// completes whatever interaction context the browser happens to be carrying — including one
/// planted by an attacker's page navigating the victim to a valid authorization request for a
/// client the attacker registered, whose PKCE verifier, <c>state</c> and <c>nonce</c> the
/// attacker chose. Requiring the identifier to come back through the page means a user who
/// reached the login page on their own has nothing to attach a planted context to.
/// </para>
/// <para>
/// It also turns concurrent tabs from a silent failure into a loud one: without the check, tab A's
/// sign-in would complete tab B's authorization request and send a code to B's client.
/// </para>
/// </remarks>
internal static class InteractionHandoff
{
    /// <summary>
    /// The query parameter carrying the interaction identifier. Deliberately short and opaque: it
    /// is an identifier, not a URL, so it carries no open-redirect surface of its own.
    /// </summary>
    public const string InteractionIdParameter = "zkd_i";

    /// <summary>Builds the redirect to a host interaction page for the given interaction.</summary>
    public static string BuildRedirectUrl(string path, string interactionId) =>
        QueryHelpers.AddQueryString(path, InteractionIdParameter, interactionId);

    /// <summary>
    /// Reads the interaction identifier the page was reached with — from the query string, then
    /// from the form body for a page that posts it as a hidden field. Returns
    /// <see langword="null"/> when it is absent, empty, or supplied more than once.
    /// </summary>
    /// <remarks>
    /// A <c>&lt;form method="post"&gt;</c> with no <c>action</c> posts to the current URL including
    /// its query string, so the common login page needs to do nothing at all. Reading the form as
    /// well covers the page that regenerates its action from routing and passes the value back
    /// explicitly.
    /// </remarks>
    public static async ValueTask<string?> ReadInteractionIdAsync(HttpRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);

        if (Single(request.Query[InteractionIdParameter]) is { } fromQuery)
            return fromQuery;

        if (!request.HasFormContentType)
            return null;

        var form = await request.ReadFormAsync(request.HttpContext.RequestAborted).ConfigureAwait(false);
        return Single(form[InteractionIdParameter]);
    }

    /// <summary>
    /// A parameter supplied twice is refused rather than resolved, matching how the authorization
    /// endpoint treats every duplicated parameter: picking one of two values is a decision an
    /// attacker gets to influence.
    /// </summary>
    private static string? Single(Microsoft.Extensions.Primitives.StringValues values) =>
        values.Count == 1 && !string.IsNullOrEmpty(values[0]) ? values[0] : null;
}
