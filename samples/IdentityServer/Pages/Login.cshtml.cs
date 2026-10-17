using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using ZeeKayDa.Auth.AspNetCore.Interaction;
using ZeeKayDa.Auth.Authorization;
using ZeeKayDa.Auth.Samples.IdentityServer.Users;

namespace ZeeKayDa.Auth.Samples.IdentityServer.Pages;

public sealed class LoginModel(UserStore users, LoginInteraction login) : PageModel
{
    [BindProperty]
    public string? Username { get; set; }

    public bool Failed { get; private set; }

    /// <summary>Who this browser is already signed in as, for the "keep them signed in" choice.</summary>
    public IReadOnlyList<SignedInAccount> SignedInAccounts { get; private set; } = [];

    public async Task OnGetAsync()
    {
        // The client may have said who is signing in (login_hint); pre-fill it as a convenience.
        // Razor encodes it like any other value, and it is never used to sign anyone in.
        var request = await login.TryGetRequestAsync(HttpContext.RequestAborted);
        Username ??= request?.LoginHint;
        SignedInAccounts = request?.SignedInAccounts ?? [];
    }

    public async Task OnPostAsync(string? password, string? action, bool keepOthersSignedIn)
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
        // request, writing the response itself. The username is what the account picker shows, and
        // what a client's login_hint is matched against. Adding keeps the accounts this browser is
        // already signed in to; signing in replaces them, the safe choice on a shared computer.
        if (keepOthersSignedIn)
            await login.AddAccountAsync(user.Subject, AuthenticationMethods.Password, user.Username);
        else
            await login.SignInAsync(user.Subject, AuthenticationMethods.Password, user.Username);
    }
}
