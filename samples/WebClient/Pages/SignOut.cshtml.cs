using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace ZeeKayDa.Auth.Samples.WebClient.Pages;

/// <summary>
/// Signs the user out. A Razor Pages POST, so the antiforgery token keeps another site from signing
/// the user out behind their back.
/// </summary>
public sealed class SignOutModel : PageModel
{
    /// <summary>A GET has nothing to do: signing out is only ever a POST.</summary>
    public IActionResult OnGet() => RedirectToPage("/Index");

    /// <summary>
    /// Signing out of the cookie ends the session here; signing out of the OpenID Connect scheme
    /// sends the browser to the server's end-session endpoint, which returns it to
    /// /signout-callback-oidc and from there to the home page.
    /// </summary>
    public IActionResult OnPost() => SignOut(
        new AuthenticationProperties { RedirectUri = "/" },
        CookieAuthenticationDefaults.AuthenticationScheme,
        OpenIdConnectDefaults.AuthenticationScheme);
}
