using System.Security.Claims;
using ZeeKayDa.Auth.Authorization;

namespace ZeeKayDa.Auth.AspNetCore.Interaction;

/// <summary>
/// The host login page's completion of an authorization request. One of the per-page interaction
/// services: the host owns the page, the credential check and the user store; this service owns
/// the protocol.
/// </summary>
/// <remarks>
/// <para>
/// The page needs no <c>ReturnUrl</c>, no scheme name and no cookie name — the framework redirected
/// the user here and knows which authorization request is being resumed. The one thing the page
/// must preserve is the <c>zkd_i</c> query parameter it was reached with, which an ordinary
/// <c>&lt;form method="post"&gt;</c> does by default.
/// </para>
/// </remarks>
public interface ILoginInteraction
{
    /// <summary>
    /// Whether the page should render a credential form of its own — the value of
    /// <c>AuthorizationEndpoint.Interaction.SupportsLocalSignIn</c>. Configuration, frozen at
    /// startup.
    /// </summary>
    bool LocalLoginEnabled { get; }

    /// <summary>
    /// The external providers the host registered through <c>WithProviders</c>, in registration
    /// order, for the page to render as a choice. Configuration, frozen at startup; empty when
    /// none are registered.
    /// </summary>
    /// <remarks>
    /// The page renders a credential form, a row of provider buttons, or both — the login page is
    /// also the provider-selection page. A <see cref="ProviderDescriptor.Id"/> is handed back to
    /// the framework to select that provider, never written by the page.
    /// </remarks>
    IReadOnlyList<ProviderDescriptor> Providers { get; }

    /// <summary>
    /// Establishes the SSO session for <paramref name="principal"/> and continues the
    /// authorization request that led here.
    /// </summary>
    /// <param name="principal">
    /// The authenticated user. Must carry a <c>sub</c> or
    /// <see cref="ClaimTypes.NameIdentifier"/> claim; claims in the framework's reserved
    /// <c>zkd:</c> namespace are stripped.
    /// </param>
    /// <param name="authenticationMethods">
    /// How the user proved who they are, reported to the client in the <c>amr</c> claim. Use
    /// <see cref="AuthenticationMethods"/> for the registered values —
    /// <c>SignInAsync(user, AuthenticationMethods.Password)</c> — or pass your own string for a
    /// method the registry does not name. Several may be given, and RFC 8176 §2 asks that they be:
    /// a multi-factor sign-in reports <c>MultiFactor</c> alongside the individual factors.
    /// </param>
    /// <remarks>
    /// <para>
    /// <strong>Terminal.</strong> This writes and commits the response, so it must be the last
    /// thing the page does. Returning a result of your own after calling it does not reach the
    /// browser — it throws, because the response has already started.
    /// </para>
    /// <para>
    /// Passing none omits the <c>amr</c> claim rather than assuming a password. The claim is
    /// optional in OpenID Connect, and a relying party may gate a sensitive operation on what it
    /// says — so the framework states nothing about a sign-in it was told nothing about, instead
    /// of guessing a method that may not be the one used.
    /// </para>
    /// </remarks>
    /// <exception cref="ZeeKayDaInteractionException">
    /// There is no interaction to resume: the request carries no <c>zkd_i</c>, the interaction
    /// context cookie is absent or expired, or the two do not name the same interaction. The last
    /// case is what a login page that dropped the query parameter looks like — see
    /// <c>Interaction.LoginPath</c> for the fix.
    /// </exception>
    /// <exception cref="ArgumentException">
    /// An entry in <paramref name="authenticationMethods"/> is null or blank.
    /// </exception>
    Task SignInAsync(ClaimsPrincipal principal, params string[] authenticationMethods);

    /// <summary>
    /// Ends the authorization request without signing anyone in, answering the client with
    /// <c>access_denied</c> at its registered redirect URI. This is the Cancel button.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <strong>Terminal.</strong> This writes and commits the response, so it must be the last
    /// thing the page does. Returning a result of your own after calling it does not reach the
    /// browser — it throws, because the response has already started.
    /// </para>
    /// <para>
    /// No SSO session is established, and an existing one is left alone — cancelling one client's
    /// request does not sign the user out of another's. The interaction is discarded, so the
    /// cancelled request cannot afterwards be resumed.
    /// </para>
    /// <para>
    /// The client receives an <c>error_description</c> stating that the user cancelled at the
    /// sign-in page, so it can tell this apart from the other refusals that also answer
    /// <c>access_denied</c>.
    /// </para>
    /// <para>
    /// Reach this only from a state-changing request — a form post, not a link. A cancel wired to
    /// a <c>GET</c> anchor is triggerable cross-site by anyone who learns the interaction
    /// identifier, and ends the user's in-flight sign-in.
    /// </para>
    /// </remarks>
    /// <exception cref="ZeeKayDaInteractionException">
    /// There is no interaction to end: the request carries no <c>zkd_i</c>, the interaction context
    /// cookie is absent or expired, or the two do not name the same interaction.
    /// </exception>
    /// <exception cref="InvalidOperationException">
    /// There is no active HTTP request — the service was resolved outside one.
    /// </exception>
    Task DenyAsync();

    /// <summary>
    /// Sends the user out to one of the external providers in <see cref="Providers"/> to be
    /// authenticated there, and continues the authorization request when they return.
    /// </summary>
    /// <param name="provider">
    /// The <see cref="ProviderDescriptor.Id"/> of the provider the user picked, as the page
    /// received it from <see cref="Providers"/>.
    /// </param>
    /// <remarks>
    /// <para>
    /// <strong>Terminal.</strong> This writes and commits the response, so it must be the last
    /// thing the page does. Returning a result of your own after calling it does not reach the
    /// browser — it throws, because the response has already started.
    /// </para>
    /// <para>
    /// The page names no scheme, callback path or return URL. The framework activates the
    /// provider's handler, serves its callback, and brings the user back to establish the SSO
    /// session — through <c>ProviderOptions.OnProviderSignIn</c> first, when the host registered
    /// one. Reach this only from a state-changing request — a form post, not a link.
    /// </para>
    /// </remarks>
    /// <exception cref="ZeeKayDaInteractionException">
    /// There is no interaction to continue: the request carries no <c>zkd_i</c>, the interaction
    /// context cookie is absent or expired, or the two do not name the same interaction. Or
    /// <paramref name="provider"/> is not the identifier of a registered provider.
    /// </exception>
    /// <exception cref="ArgumentException">
    /// <paramref name="provider"/> is null or empty.
    /// </exception>
    /// <exception cref="InvalidOperationException">
    /// There is no active HTTP request — the service was resolved outside one.
    /// </exception>
    Task ChallengeAsync(string provider);

    /// <summary>
    /// The principal an external provider authenticated that
    /// <c>ProviderSignInContext.RedirectToAsync</c> parked for this page, or
    /// <see langword="null"/> when there is none: the redirect did not come from there, the
    /// parked principal has expired, or it belongs to another interaction. A page that gets
    /// <see langword="null"/> has nothing to link and should say so, not fail.
    /// </summary>
    /// <remarks>
    /// The parked principal is single-use: the <see cref="SignInAsync"/> that completes its
    /// interaction consumes it, whatever principal the page passes. A page that links the external
    /// identity to a local account passes its own principal; one that merely collected more passes
    /// this one, with what it collected added.
    /// </remarks>
    /// <exception cref="ZeeKayDaInteractionException">
    /// The request carries no <c>zkd_i</c>, so there is no interaction to read a parked principal
    /// for. The framework adds it to the URL it redirects the page to; a form that regenerates its
    /// action from routing drops it.
    /// </exception>
    /// <exception cref="InvalidOperationException">
    /// There is no active HTTP request — the service was resolved outside one.
    /// </exception>
    Task<PendingPrincipal?> GetPendingPrincipalAsync();
}
