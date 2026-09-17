using Microsoft.AspNetCore.Mvc.RazorPages;
using ZeeKayDa.Auth.AspNetCore.Interaction;

namespace ZeeKayDa.Auth.Samples.IdentityServer.Pages;

public sealed class ConsentModel(IConsentInteraction consent) : PageModel
{
    /// <summary>What to ask, or <see langword="null"/> when there is nothing left to ask about.</summary>
    public ConsentRequest? ConsentRequest { get; private set; }

    public async Task OnGetAsync() => ConsentRequest = await consent.TryGetRequestAsync(HttpContext.RequestAborted);

    public async Task OnPostAsync(string? action)
    {
        // Both calls are terminal: the framework writes the response, and the handler just ends.
        // That includes a form submitted twice, or after the request expired: the framework sends
        // the user back to the application to start again.
        if (action == "allow")
        {
            // Grants what was asked; a page offering per-scope choices would pass the subset.
            var request = await consent.TryGetRequestAsync(HttpContext.RequestAborted);
            await consent.GrantAsync(request?.Scopes ?? []);
        }
        else
        {
            await consent.DenyAsync();
        }
    }
}
