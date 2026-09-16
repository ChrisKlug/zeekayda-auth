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
        var request = await logout.GetRequestAsync(HttpContext.RequestAborted);
        ClientName = request.Client is { } client ? client.DisplayName ?? client.ClientId : null;
        Username = users.FindBySubject(request.Subject)?.Username ?? request.Subject;
    }

    // Terminal: the framework ends the session and redirects to the client, or to the signed-out page.
    public async Task OnPostAsync() => await logout.SignOutAsync();

    public string? ClientName { get; private set; }

    public string Username { get; private set; } = null!;
}
