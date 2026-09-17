using Microsoft.AspNetCore.Mvc.RazorPages;
using ZeeKayDa.Auth.AspNetCore.Interaction;

namespace ZeeKayDa.Auth.Samples.IdentityServer.Pages;

public sealed class ConsentModel(IConsentInteraction consent) : PageModel
{
    /// <summary>What to ask, or <see langword="null"/> when there is nothing left to ask about.</summary>
    public ConsentRequest? ConsentRequest { get; private set; }

    public async Task OnGetAsync() => ConsentRequest = await consent.TryGetRequestAsync(HttpContext.RequestAborted);

    public async Task OnPostAsync(string? action, string[] scope)
    {
        // Both calls are terminal: the framework writes the response, and the handler just ends.
        // That includes a form submitted twice, or after the request expired: the framework sends
        // the user back to the application to start again.
        if (action == "allow")
        {
            // The scopes the page showed, posted back with the form. A page offering per-scope
            // choices posts the ticked subset; the framework grants nothing that was not asked.
            await consent.GrantAsync(scope);
        }
        else
        {
            await consent.DenyAsync();
        }
    }
}
