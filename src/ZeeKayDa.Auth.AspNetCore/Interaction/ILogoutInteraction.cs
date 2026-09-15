namespace ZeeKayDa.Auth.AspNetCore.Interaction;

/// <summary>
/// The host logout page's confirmation of a sign-out. One of the per-page interaction services:
/// the host owns the page, this service owns the protocol.
/// </summary>
/// <remarks>
/// <para>
/// Used by the page at <c>EndSessionEndpoint.LogoutPath</c>. The framework redirects there when
/// the user must be asked before being signed out, carrying a <c>zkd_i</c> query parameter the
/// page must preserve across its own form post, on the same terms as the login page.
/// </para>
/// <para>
/// There is nothing to call when the user declines. A sign-out has no error response to the
/// client, so a "stay signed in" button can go wherever the host likes, and the unanswered
/// sign-out expires on its own.
/// </para>
/// </remarks>
public interface ILogoutInteraction
{
    /// <summary>
    /// Returns the sign-out the page is asked to confirm, for the page to render.
    /// </summary>
    /// <remarks>
    /// The response this is read from is stamped <c>frame-ancestors 'none'</c>,
    /// <c>X-Frame-Options: DENY</c> and <c>no-store</c>, so the page taking a one-click decision
    /// cannot be framed or cached. A page that renders without calling this — a fixed "Sign out?"
    /// page that only posts — gets none of those headers and must set its own.
    /// </remarks>
    /// <param name="cancellationToken">A token to cancel the operation.</param>
    /// <exception cref="ZeeKayDaInteractionException">
    /// There is no sign-out to confirm: the request carries no <c>zkd_i</c>, or names one this
    /// browser is not carrying — it expired, was already completed, or was started in another
    /// browser.
    /// </exception>
    /// <exception cref="ZeeKayDaStoreException">The interaction store could not be read.</exception>
    /// <exception cref="InvalidOperationException">
    /// There is no active HTTP request — the service was resolved outside one.
    /// </exception>
    /// <exception cref="OperationCanceledException"><paramref name="cancellationToken"/> was cancelled.</exception>
    Task<LogoutRequest> GetRequestAsync(CancellationToken cancellationToken = default);

    /// <summary>
    /// Signs the user out and sends them on: to the client's registered post-logout redirect URI
    /// when the sign-out named one, carrying the client's <c>state</c>, and to the signed-out page
    /// otherwise. This is the Sign out button.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <strong>Terminal.</strong> This writes and commits the response, so it must be the last
    /// thing the page does. A Razor Pages handler or controller action can simply end after it:
    /// the framework skips MVC's result, including one the handler returns. Anywhere else,
    /// returning a result of your own after calling it throws, because the response has already
    /// started.
    /// </para>
    /// <para>
    /// The SSO session ends, and so does every authorization request this browser still has in
    /// flight. The redirect URI is checked again against the client's registration as it stands
    /// now, so one the operator removed while the page was open is not used.
    /// </para>
    /// <para>
    /// Only a <c>POST</c> — the form's submission — is accepted, and that is checked before
    /// anything is read. A sign-out wired to the <c>GET</c> that renders the page would sign the
    /// user out the moment they arrived, which is exactly what the confirmation exists to prevent.
    /// </para>
    /// </remarks>
    /// <exception cref="ZeeKayDaInteractionException">
    /// There is no sign-out to complete: the request carries no <c>zkd_i</c>, or names one this
    /// browser is not carrying — it expired, was already completed, or was started in another
    /// browser. Or the browser no longer holds the session the sign-out was started for, because
    /// that session ended or the user signed in again while the page was open.
    /// </exception>
    /// <exception cref="ZeeKayDaStoreException">
    /// The interaction store could not be read. Fail-closed: nobody was signed out.
    /// </exception>
    /// <exception cref="InvalidOperationException">
    /// The request is not a <c>POST</c>, or there is no active HTTP request — the service was
    /// resolved outside one.
    /// </exception>
    Task SignOutAsync();
}
