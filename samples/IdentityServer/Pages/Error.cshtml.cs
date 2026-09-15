using Microsoft.AspNetCore.Mvc.RazorPages;
using ZeeKayDa.Auth.AspNetCore.Interaction;

namespace ZeeKayDa.Auth.Samples.IdentityServer.Pages;

/// <summary>
/// Renders an authorization error the framework could not send back to the client — an unknown
/// client or an unregistered redirect URI, where redirecting would be unsafe.
/// </summary>
public sealed class ErrorModel(IErrorInteraction errors) : PageModel
{
    public AuthorizationErrorDetails? Details { get; private set; }

    public async Task OnGetAsync() => Details = await errors.GetErrorAsync(HttpContext.RequestAborted);
}
