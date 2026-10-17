using Microsoft.AspNetCore.Mvc.RazorPages;
using ZeeKayDa.Auth.AspNetCore.Interaction;
using ZeeKayDa.Auth.Samples.IdentityServer.Users;

namespace ZeeKayDa.Auth.Samples.IdentityServer.Pages;

/// <summary>
/// Asks the user to confirm a sign-out the framework was asked for. Declining needs no call: the
/// "Stay signed in" link leaves, and the unanswered sign-out expires on its own.
/// </summary>
public sealed class LogoutModel(UserStore users, LogoutInteraction logout) : PageModel
{
    public async Task OnGetAsync()
    {
        if (await logout.TryGetRequestAsync(HttpContext.RequestAborted) is not { } request)
            return;

        HasRequest = true;
        ClientName = request.Client is { } client ? client.DisplayName ?? client.ClientId : null;
        Username = users.FindBySubject(request.Subject)?.Username ?? request.Subject;
        OtherAccounts = request.SignedInAccounts.Count - 1;
    }

    // Terminal: the framework ends the session and redirects to the client, or to the signed-out
    // page — including for a form submitted twice, where the user is already signed out. "All"
    // signs out every account this browser holds, for a shared computer.
    public async Task OnPostAsync(string? scope)
    {
        if (scope == "all")
            await logout.SignOutAllAsync();
        else
            await logout.SignOutAsync();
    }

    /// <summary>How many other accounts this browser is signed in to, which "Sign out of all accounts" also ends.</summary>
    public int OtherAccounts { get; private set; }

    /// <summary>Whether there is a sign-out to confirm; it may have expired or been answered already.</summary>
    public bool HasRequest { get; private set; }

    public string? ClientName { get; private set; }

    public string? Username { get; private set; }
}
