using Microsoft.AspNetCore.Mvc.RazorPages;
using ZeeKayDa.Auth.AspNetCore.Interaction;
using ZeeKayDa.Auth.Samples.IdentityServer.Users;

namespace ZeeKayDa.Auth.Samples.IdentityServer.Pages;

/// <summary>
/// Asks the user to confirm a sign-out the framework was asked for. Declining needs no call: the
/// "Stay signed in" link leaves, and the unanswered sign-out expires on its own.
/// </summary>
public sealed class LogoutModel(UserStore users, ILogoutInteraction logout) : PageModel
{
    public async Task OnGetAsync()
    {
        if (await logout.TryGetRequestAsync(HttpContext.RequestAborted) is not { } request)
            return;

        HasRequest = true;
        ClientName = request.Client is { } client ? client.DisplayName ?? client.ClientId : null;
        Username = users.FindBySubject(request.Subject)?.Username ?? request.Subject;
    }

    // Terminal: the framework ends the session and redirects to the client, or to the signed-out
    // page — including for a form submitted twice, where the user is already signed out.
    public async Task OnPostAsync() => await logout.SignOutAsync();

    /// <summary>Whether there is a sign-out to confirm; it may have expired or been answered already.</summary>
    public bool HasRequest { get; private set; }

    public string? ClientName { get; private set; }

    public string? Username { get; private set; }
}
