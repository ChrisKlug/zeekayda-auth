using Microsoft.AspNetCore.Mvc.RazorPages;
using ZeeKayDa.Auth.AspNetCore.Interaction;

namespace ZeeKayDa.Auth.Samples.IdentityServer.Pages;

public sealed class ConsentModel(IConsentInteraction consent) : PageModel
{
    public ConsentRequest ConsentRequest { get; private set; } = null!;

    public async Task OnGetAsync() => ConsentRequest = await consent.GetRequestAsync(HttpContext.RequestAborted);

    public async Task OnPostAsync(string? action)
    {
        // Both calls are terminal: the framework writes the response, and the handler just ends.
        if (action == "allow")
        {
            // Grants what was asked; a page offering per-scope choices would pass the subset.
            var request = await consent.GetRequestAsync(HttpContext.RequestAborted);
            await consent.GrantAsync(request.Scopes);
        }
        else
        {
            await consent.DenyAsync();
        }
    }
}
