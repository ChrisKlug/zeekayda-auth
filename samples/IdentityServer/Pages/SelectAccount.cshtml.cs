using Microsoft.AspNetCore.Mvc.RazorPages;
using ZeeKayDa.Auth.AspNetCore.Interaction;

namespace ZeeKayDa.Auth.Samples.IdentityServer.Pages;

/// <summary>
/// The account picker, for a client that sends prompt=select_account. Picking an account asks for
/// no password: the browser is already signed in to it.
/// </summary>
public sealed class SelectAccountModel(AccountSelectionInteraction picker) : PageModel
{
    public AccountSelectionRequest? SelectionRequest { get; private set; }

    public async Task OnGetAsync() =>
        SelectionRequest = await picker.TryGetRequestAsync(HttpContext.RequestAborted);

    // Each call is terminal: the framework continues the authorization request, sends the user on
    // to the login page, or answers the client, and writes the response itself.
    public async Task OnPostAsync(string? account, string? action)
    {
        if (action == "cancel")
            await picker.DenyAsync();
        else if (action == "another" || account is null)
            await picker.UseAnotherAccountAsync();
        else
            await picker.SelectAsync(account);
    }
}
