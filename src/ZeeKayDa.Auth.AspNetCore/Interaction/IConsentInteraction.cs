namespace ZeeKayDa.Auth.AspNetCore.Interaction;

/// <summary>
/// The host consent page's completion of an authorization request. One of the per-page
/// interaction services: the host owns the page and its wording; this service owns the protocol.
/// </summary>
/// <remarks>
/// <para>
/// The framework redirects the user here after sign-in when the client requires consent, at the
/// configured <c>AuthorizationEndpoint.Interaction.ConsentPath</c>. As with the login page, the
/// one thing the page must preserve is the <c>zkd_i</c> query parameter it was reached with,
/// which an ordinary <c>&lt;form method="post"&gt;</c> does by default.
/// </para>
/// <para>
/// Every method is bound to the interaction the request is addressed to <em>and</em> to the
/// session that was authenticated for it: a consent decision is recorded by the user it was
/// asked of, never by whoever holds the browser afterwards.
/// </para>
/// <para>
/// <strong>Nothing to continue is answered, not thrown.</strong> When a terminal method finds no
/// interaction left to complete — the request carries no <c>zkd_i</c>; the interaction expired, was
/// already completed or was started in another browser; the session that authenticated it is no longer the one the browser holds; the client
/// is no longer registered; or another response completed it while
/// this one was being prepared — the framework answers the request itself. It sends the browser to
/// the client's registered <c>InitiateLoginUri</c>, with <c>iss</c>, to start again when the browser
/// can still say which client it came from, and to the error page with
/// <see cref="AuthorizationErrorKind.NothingToContinue"/> otherwise. The call is terminal either way.
/// A missing <c>zkd_i</c> is also logged as a warning, since a form that drops it causes the same
/// answer on every submission.
/// </para>
/// </remarks>
public interface IConsentInteraction
{
    /// <summary>
    /// What the page should ask: the client, the scopes it wants, and who is being asked.
    /// </summary>
    /// <param name="cancellationToken">Cancels the read; pass the request's own token.</param>
    /// <remarks>
    /// The page takes a one-click decision, so the response this is called from is marked
    /// unframeable (<c>Content-Security-Policy: frame-ancestors 'none'</c>, appended alongside
    /// any policy of the host's, and <c>X-Frame-Options: DENY</c>) and uncacheable
    /// (<c>Cache-Control: no-store</c>). A page renders nothing meaningful without this call, so
    /// every rendered consent page carries the protection; one that renders without calling it is
    /// on its own.
    /// </remarks>
    /// <exception cref="ZeeKayDaInteractionException">
    /// There is no interaction to ask about: the request carries no <c>zkd_i</c>, or names an
    /// interaction this browser is not carrying — it expired, was already completed, or was started
    /// in another browser; or the session that authenticated the request is no longer the one the
    /// browser holds; or the client that sent the request is no longer registered or no longer
    /// lists its redirect URI. A page that wants to render its own message for these cases calls
    /// <see cref="TryGetRequestAsync"/> instead.
    /// </exception>
    /// <exception cref="ZeeKayDaStoreException">
    /// The interaction store could not be reached. Fail-closed: nothing is reported as absent.
    /// </exception>
    /// <exception cref="InvalidOperationException">
    /// There is no active HTTP request — the service was resolved outside one.
    /// </exception>
    /// <exception cref="OperationCanceledException">
    /// <paramref name="cancellationToken"/> was cancelled.
    /// </exception>
    Task<ConsentRequest> GetRequestAsync(CancellationToken cancellationToken = default);

    /// <summary>
    /// What the page should ask, or <see langword="null"/> when there is nothing to ask about — for
    /// a page that renders its own "nothing to continue" message.
    /// </summary>
    /// <param name="cancellationToken">Cancels the read; pass the request's own token.</param>
    /// <remarks>
    /// Exactly <see cref="GetRequestAsync"/>, including the headers it stamps, except that each case
    /// <see cref="GetRequestAsync"/> reports with <see cref="ZeeKayDaInteractionException"/> returns
    /// <see langword="null"/> instead. A request with no <c>zkd_i</c> is logged as a warning, since
    /// a form that drops it looks like this on every submission.
    /// </remarks>
    /// <exception cref="ZeeKayDaStoreException">
    /// The interaction store could not be reached. Fail-closed: nothing is reported as absent.
    /// </exception>
    /// <exception cref="InvalidOperationException">
    /// There is no active HTTP request — the service was resolved outside one.
    /// </exception>
    /// <exception cref="OperationCanceledException">
    /// <paramref name="cancellationToken"/> was cancelled.
    /// </exception>
    Task<ConsentRequest?> TryGetRequestAsync(CancellationToken cancellationToken = default);

    /// <summary>
    /// Records the user's consent to <paramref name="scopes"/> and continues the authorization
    /// request.
    /// </summary>
    /// <param name="scopes">
    /// The scopes the user agreed to, typically the boxes they ticked. Only entries in
    /// <see cref="ConsentRequest.Scopes"/> count; anything else is dropped without comment, so
    /// a page cannot widen what was asked.
    /// </param>
    /// <remarks>
    /// <para>
    /// <strong>Terminal.</strong> This writes and commits the response, so it must be the last
    /// thing the page does. A Razor Pages handler or controller action can simply end after it:
    /// the framework skips MVC's result, including one the handler returns. Anywhere else,
    /// returning a result of your own after calling it throws, because the response has already
    /// started.
    /// </para>
    /// <para>
    /// A grant that leaves out <c>openid</c> is a refusal to be identified to the client, and is
    /// answered as one: the client receives <c>access_denied</c>, as from <see cref="DenyAsync"/>.
    /// A page that does not want to offer that choice renders <c>openid</c> as required.
    /// </para>
    /// <para>
    /// Only a <c>POST</c> — the consent form's submission — is accepted, and that is checked
    /// before anything is read. The framework arrives at the page with a <c>GET</c>, so a page
    /// that decided in its render handler would grant every request on arrival.
    /// </para>
    /// <para>
    /// With nothing left to complete, this answers the request itself rather than throwing — see the
    /// interface remarks.
    /// </para>
    /// </remarks>
    /// <exception cref="ZeeKayDaStoreException">
    /// The interaction store or the authorization code store could not be reached. Fail-closed:
    /// nothing was issued.
    /// </exception>
    /// <exception cref="ArgumentNullException">
    /// <paramref name="scopes"/> is null.
    /// </exception>
    /// <exception cref="ArgumentException">
    /// An entry in <paramref name="scopes"/> is null or blank.
    /// </exception>
    /// <exception cref="InvalidOperationException">
    /// The request is not a <c>POST</c>, or there is no active HTTP request — the service was
    /// resolved outside one.
    /// </exception>
    Task GrantAsync(IEnumerable<string> scopes);

    /// <summary>
    /// Ends the authorization request without consent, answering the client with
    /// <c>access_denied</c> at its registered redirect URI. This is the Deny button.
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
    /// The SSO session is left alone — declining one client does not sign the user out of
    /// another. The interaction is discarded, so the declined request cannot afterwards be
    /// resumed. The client receives an <c>error_description</c> stating that the user declined
    /// at the consent page, so it can tell this apart from the other refusals that also answer
    /// <c>access_denied</c>.
    /// </para>
    /// <para>
    /// Only a <c>POST</c> — the form's submission — is accepted, and that is checked before
    /// anything is read. A deny reachable by a link could be triggered cross-site by anyone who
    /// learned the interaction identifier, ending the user's in-flight request.
    /// </para>
    /// <para>
    /// With nothing left to complete, this answers the request itself rather than throwing — see the
    /// interface remarks.
    /// </para>
    /// </remarks>
    /// <exception cref="ZeeKayDaStoreException">
    /// The interaction store or the authorization code store could not be reached. Fail-closed:
    /// the client was told nothing.
    /// </exception>
    /// <exception cref="InvalidOperationException">
    /// The request is not a <c>POST</c>, or there is no active HTTP request — the service was
    /// resolved outside one.
    /// </exception>
    Task DenyAsync();
}
