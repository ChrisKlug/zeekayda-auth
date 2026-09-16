using System.Security.Claims;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using ZeeKayDa.Auth.AspNetCore.Interaction;
using ZeeKayDa.Auth.Authorization;
using ZeeKayDa.Auth.Samples.IdentityServer.Users;

namespace ZeeKayDa.Auth.Samples.IdentityServer.Pages;

public sealed class LoginModel(UserStore users, ILoginInteraction login) : PageModel
{
    [BindProperty]
    public string? Username { get; set; }

    public bool Failed { get; private set; }

    public async Task OnPostAsync(string? password, string? action)
    {
        if (action == "cancel")
        {
            // Terminal: the framework answers the client with access_denied, and the handler just
            // ends — the framework skips rendering the page.
            await login.DenyAsync();
            return;
        }

        if (users.Validate(Username ?? string.Empty, password ?? string.Empty) is not { } user)
        {
            // Not terminal: the handler ending renders the page again, with the error.
            Failed = true;
            return;
        }

        // Terminal too: the framework establishes the session and continues the authorization
        // request, writing the response itself.
        var identity = new ClaimsIdentity([new Claim("sub", user.Subject)], "pwd");
        await login.SignInAsync(new ClaimsPrincipal(identity), AuthenticationMethods.Password);
    }
}
