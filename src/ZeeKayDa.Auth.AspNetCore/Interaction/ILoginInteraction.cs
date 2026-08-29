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
    /// <strong>Terminal.</strong> This writes the response, so it must be the last thing the page
    /// does. Returning a result of your own after calling it will not reach the browser.
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
}
