using System.Security.Claims;

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
    /// <param name="amr">
    /// The authentication method reference for how the user proved who they are — <c>pwd</c> for
    /// a password, <c>mfa</c>, <c>otp</c>, and so on (RFC 8176).
    /// </param>
    /// <remarks>
    /// <strong>Terminal.</strong> This writes the response, so it must be the last thing the page
    /// does. Returning a result of your own after calling it will not reach the browser.
    /// </remarks>
    /// <exception cref="ZeeKayDaInteractionException">
    /// There is no interaction to resume: the request carries no <c>zkd_i</c>, the interaction
    /// context cookie is absent or expired, or the two do not name the same interaction. The last
    /// case is what a login page that dropped the query parameter looks like — see
    /// <c>Interaction.LoginPath</c> for the fix.
    /// </exception>
    Task SignInAsync(ClaimsPrincipal principal, string amr);
}
