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
    /// the protection is a guarantee rather than guidance.
    /// </remarks>
    /// <exception cref="ZeeKayDaInteractionException">
    /// There is no interaction to ask about: the request carries no <c>zkd_i</c>, the interaction
    /// context cookie is absent or expired, the two do not name the same interaction, the session
    /// that authenticated the request is no longer the one the browser holds, or the client that
    /// sent the request is no longer registered.
    /// </exception>
    /// <exception cref="InvalidOperationException">
    /// There is no active HTTP request — the service was resolved outside one.
    /// </exception>
    /// <exception cref="OperationCanceledException">
    /// <paramref name="cancellationToken"/> was cancelled.
    /// </exception>
    Task<ConsentRequest> GetRequestAsync(CancellationToken cancellationToken = default);

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
    /// thing the page does. Returning a result of your own after calling it does not reach the
    /// browser — it throws, because the response has already started.
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
    /// </remarks>
    /// <exception cref="ZeeKayDaInteractionException">
    /// There is no interaction to complete: the request carries no <c>zkd_i</c>, the interaction
    /// context cookie is absent or expired, the two do not name the same interaction, the session
    /// that authenticated the request is no longer the one the browser holds, or the client that
    /// sent the request is no longer registered.
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
    /// thing the page does. Returning a result of your own after calling it does not reach the
    /// browser — it throws, because the response has already started.
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
    /// </remarks>
    /// <exception cref="ZeeKayDaInteractionException">
    /// There is no interaction to end: the request carries no <c>zkd_i</c>, the interaction
    /// context cookie is absent or expired, the two do not name the same interaction, the session
    /// that authenticated the request is no longer the one the browser holds, or the client that
    /// sent the request is no longer registered.
    /// </exception>
    /// <exception cref="InvalidOperationException">
    /// The request is not a <c>POST</c>, or there is no active HTTP request — the service was
    /// resolved outside one.
    /// </exception>
    Task DenyAsync();
}
