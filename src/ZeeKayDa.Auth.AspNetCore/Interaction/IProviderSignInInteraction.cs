using System.Security.Claims;
using ZeeKayDa.Auth.Authorization;

namespace ZeeKayDa.Auth.AspNetCore.Interaction;

/// <summary>
/// The host page's completion of an external sign-in that <c>ProviderSignInContext.RedirectToAsync</c>
/// parked: the collect-more page, or the account-linking page. One of the per-page interaction
/// services: the host owns the page and what it collects; this service owns the protocol.
/// </summary>
/// <remarks>
/// <para>
/// The page needs no scheme name and no cookie name — the framework redirected the user here and
/// knows which authorization request, and which parked principal, is being finished. The one
/// thing the page must preserve is the <c>zkd_i</c> query parameter it was reached with, which an
/// ordinary <c>&lt;form method="post"&gt;</c> does by default.
/// </para>
/// <para>
/// A page that only collects what the provider did not supply passes the collected claims to
/// <see cref="SignInAsync(Claim[])"/>, and the framework builds the session principal the way it
/// does when no page is involved: the provider's claims under the derived subject, never the
/// upstream one. A page that links the external identity to a local account passes that account's
/// own principal to <see cref="SignInAsync(ClaimsPrincipal, string[])"/>.
/// </para>
/// </remarks>
public interface IProviderSignInInteraction
{
    /// <summary>
    /// The principal the external provider authenticated, parked for the interaction this request
    /// is addressed to, or <see langword="null"/> when there is none: the redirect did not come
    /// from <c>RedirectToAsync</c>, the parked principal has expired, or it belongs to another
    /// interaction. A page that gets <see langword="null"/> has nothing to finish and should say
    /// so, not fail.
    /// </summary>
    /// <param name="cancellationToken">Cancels the read; pass the request's own token.</param>
    /// <exception cref="ZeeKayDaInteractionException">
    /// The request carries no <c>zkd_i</c>, so there is no interaction to read a parked principal
    /// for. The framework adds it to the URL it redirects the page to; a form that regenerates its
    /// action from routing drops it.
    /// </exception>
    /// <exception cref="ZeeKayDaStoreException">
    /// The interaction store could not be reached. Fail-closed: a parked principal that cannot be
    /// read is not reported as absent, since the page would then tell the user there is nothing
    /// to finish.
    /// </exception>
    /// <exception cref="InvalidOperationException">
    /// There is no active HTTP request — the service was resolved outside one.
    /// </exception>
    /// <exception cref="OperationCanceledException">
    /// <paramref name="cancellationToken"/> was cancelled.
    /// </exception>
    Task<PendingPrincipal?> GetAsync(CancellationToken cancellationToken = default);

    /// <summary>
    /// Establishes the SSO session for the parked principal, with <paramref name="claims"/> added,
    /// and continues the authorization request that led here.
    /// </summary>
    /// <param name="claims">
    /// What the page collected, added alongside the provider's claims. The subject is the
    /// framework's: a <c>sub</c> or <see cref="ClaimTypes.NameIdentifier"/> claim is refused,
    /// and claims in the reserved <c>zkd:</c> namespace are stripped. Pass none to promote the
    /// parked principal as it is.
    /// </param>
    /// <remarks>
    /// <para>
    /// <strong>Terminal.</strong> This writes and commits the response, so it must be the last
    /// thing the page does. Returning a result of your own after calling it does not reach the
    /// browser — it throws, because the response has already started.
    /// </para>
    /// <para>
    /// The session holds what an external sign-in with no page involved would hold: the
    /// provider's claims under a subject derived from the provider, the subject claim's issuer
    /// and the upstream subject together, plus what was collected. No <c>amr</c> is reported,
    /// since the framework was told nothing about how the user proved who they are at the
    /// provider. The parked principal is consumed.
    /// </para>
    /// </remarks>
    /// <exception cref="ZeeKayDaInteractionException">
    /// There is no external sign-in to finish: the request carries no <c>zkd_i</c>, or names an
    /// interaction this browser is not carrying — it expired, was already completed, or was
    /// started in another browser — or no principal is parked for it, because it expired or was
    /// already consumed. Or the parked principal carries no subject on an authenticated identity,
    /// or a subject claim naming no issuer. Or another response completed the interaction while
    /// this one was being prepared.
    /// </exception>
    /// <exception cref="ZeeKayDaStoreException">
    /// The interaction store or the authorization code store could not be reached. Fail-closed:
    /// nothing was signed in or issued.
    /// </exception>
    /// <exception cref="ArgumentException">
    /// An entry in <paramref name="claims"/> is null, or names the subject.
    /// </exception>
    /// <exception cref="InvalidOperationException">
    /// The request is not a <c>POST</c> — only the form's submission may sign in, and that is
    /// checked before anything is read — or there is no active HTTP request.
    /// </exception>
    Task SignInAsync(params Claim[] claims);

    /// <summary>
    /// Establishes the SSO session for <paramref name="principal"/> — a local account the page
    /// linked the external identity to — and continues the authorization request that led here.
    /// </summary>
    /// <param name="principal">
    /// The account the session is for. Must carry a <c>sub</c> or
    /// <see cref="ClaimTypes.NameIdentifier"/> claim; claims in the framework's reserved
    /// <c>zkd:</c> namespace are stripped.
    /// </param>
    /// <param name="authenticationMethods">
    /// How the user proved who they are, reported to the client in the <c>amr</c> claim. Use
    /// <see cref="AuthenticationMethods"/> for the registered values, or pass your own string for
    /// a method the registry does not name. Passing none omits the claim.
    /// </param>
    /// <remarks>
    /// <para>
    /// <strong>Terminal.</strong> This writes and commits the response, so it must be the last
    /// thing the page does. Returning a result of your own after calling it does not reach the
    /// browser — it throws, because the response has already started.
    /// </para>
    /// <para>
    /// Linking can be more involved than adding a claim — matching an existing account, creating
    /// one, asking the user to sign in locally first — so the session holds the principal the
    /// page built, subject included, exactly as the login page's sign-in does. The parked
    /// principal is consumed, and the provider that parked it is recorded on the request.
    /// </para>
    /// </remarks>
    /// <exception cref="ZeeKayDaInteractionException">
    /// There is no external sign-in to finish: the request carries no <c>zkd_i</c>, or names an
    /// interaction this browser is not carrying — it expired, was already completed, or was
    /// started in another browser — or no principal is parked for it, because it expired or was
    /// already consumed. Or <paramref name="principal"/> carries no subject. Or another response
    /// completed the interaction while this one was being prepared.
    /// </exception>
    /// <exception cref="ZeeKayDaStoreException">
    /// The interaction store or the authorization code store could not be reached. Fail-closed:
    /// nothing was signed in or issued.
    /// </exception>
    /// <exception cref="ArgumentException">
    /// An entry in <paramref name="authenticationMethods"/> is null or blank.
    /// </exception>
    /// <exception cref="InvalidOperationException">
    /// The request is not a <c>POST</c>, or there is no active HTTP request.
    /// </exception>
    Task SignInAsync(ClaimsPrincipal principal, params string[] authenticationMethods);

    /// <summary>
    /// Ends the authorization request without signing anyone in, answering the client with
    /// <c>access_denied</c> at its registered redirect URI. This is the Cancel button of the
    /// page, and a linking page's refusal.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <strong>Terminal.</strong> This writes and commits the response, so it must be the last
    /// thing the page does. Returning a result of your own after calling it does not reach the
    /// browser — it throws, because the response has already started.
    /// </para>
    /// <para>
    /// No SSO session is established, and an existing one is left alone. The interaction and the
    /// principal parked for it are discarded, so the request cannot afterwards be resumed. The
    /// client receives an <c>error_description</c> naming a refusal after sign-in at the external
    /// provider, the same one <c>ProviderSignInContext.DenyAsync</c> sends, so it can tell this
    /// apart from a cancellation at the sign-in page.
    /// </para>
    /// <para>
    /// Only a <c>POST</c> — the form's submission — is accepted, and that is checked before
    /// anything is read. A cancel wired to a <c>GET</c> anchor would be triggerable cross-site by
    /// anyone who learned the interaction identifier.
    /// </para>
    /// </remarks>
    /// <exception cref="ZeeKayDaInteractionException">
    /// There is no interaction to end: the request carries no <c>zkd_i</c>, or names an interaction
    /// this browser is not carrying — it expired, was already completed, or was started in another
    /// browser. Or another response completed the interaction while this one was being prepared.
    /// </exception>
    /// <exception cref="ZeeKayDaStoreException">
    /// The interaction store or the authorization code store could not be reached. Fail-closed:
    /// the client was told nothing.
    /// </exception>
    /// <exception cref="InvalidOperationException">
    /// The request is not a <c>POST</c>, or there is no active HTTP request.
    /// </exception>
    Task DenyAsync();
}
