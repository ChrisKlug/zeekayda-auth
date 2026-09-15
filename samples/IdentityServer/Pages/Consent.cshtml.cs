using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using ZeeKayDa.Auth.AspNetCore.Interaction;

namespace ZeeKayDa.Auth.Samples.IdentityServer.Pages;

public sealed class ConsentModel(IConsentInteraction consent) : PageModel
{
    public ConsentRequest ConsentRequest { get; private set; } = null!;

    public async Task OnGetAsync() => ConsentRequest = await consent.GetRequestAsync(HttpContext.RequestAborted);

    public async Task<IActionResult> OnPostAsync(string? action)
    {
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

        // Both calls are terminal: the framework has already written the response.
        return new EmptyResult();
    }
}
