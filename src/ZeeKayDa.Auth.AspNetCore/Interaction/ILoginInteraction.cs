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
    /// <c>zkd:</c> namespace are stripped. Copied when the call is made, as
    /// <paramref name="authenticationMethods"/> is: what was validated is what is signed in,
    /// whatever the page does to either afterwards.
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
    /// A principal an external provider parked for this interaction — one the host's page did
    /// not finish with — is discarded: the session holds <paramref name="principal"/>, and a
    /// local sign-in records no provider.
    /// </para>
    /// <para>
    /// Passing none omits the <c>amr</c> claim rather than assuming a password. The claim is
    /// optional in OpenID Connect, and a relying party may gate a sensitive operation on what it
    /// says — so the framework states nothing about a sign-in it was told nothing about, instead
    /// of guessing a method that may not be the one used.
    /// </para>
    /// </remarks>
    /// <exception cref="ZeeKayDaInteractionException">
    /// There is no interaction to resume: the request carries no <c>zkd_i</c>, or names an
    /// interaction this browser is not carrying — it expired, was already completed, was started
    /// in another browser, or the login page dropped the query parameter (see
    /// <c>Interaction.LoginPath</c> for the fix). Or another response completed the interaction
    /// while this one was being prepared.
    /// </exception>
    /// <exception cref="ZeeKayDaStoreException">
    /// The interaction store or the authorization code store could not be reached. Fail-closed:
    /// nothing was signed in or issued.
    /// </exception>
    /// <exception cref="ArgumentException">
    /// An entry in <paramref name="authenticationMethods"/> is null or blank.
    /// </exception>
    /// <exception cref="InvalidOperationException">
    /// The request is not a <c>POST</c> — only the login form's submission may sign in, and that
    /// is checked before anything is read — or there is no active HTTP request.
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
    /// Only a <c>POST</c> — the form's submission — is accepted, and that is checked before
    /// anything is read. A cancel wired to a <c>GET</c> anchor would be triggerable cross-site by
    /// anyone who learned the interaction identifier, ending the user's in-flight sign-in.
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
    /// The request is not a <c>POST</c>, or there is no active HTTP request — the service was
    /// resolved outside one.
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
    /// one. Only a <c>POST</c> — the form's submission — is accepted, and that is checked before
    /// anything is read.
    /// </para>
    /// </remarks>
    /// <exception cref="ZeeKayDaInteractionException">
    /// There is no interaction to continue: the request carries no <c>zkd_i</c>, or names an
    /// interaction this browser is not carrying — it expired, was already completed, or was started
    /// in another browser. Or <paramref name="provider"/> is not the identifier of a registered
    /// provider.
    /// </exception>
    /// <exception cref="ZeeKayDaStoreException">
    /// The interaction store could not be reached. Fail-closed: no challenge was issued.
    /// </exception>
    /// <exception cref="ArgumentException">
    /// <paramref name="provider"/> is null or empty.
    /// </exception>
    /// <exception cref="InvalidOperationException">
    /// The request is not a <c>POST</c>, or there is no active HTTP request — the service was
    /// resolved outside one.
    /// </exception>
    Task ChallengeAsync(string provider);
}
