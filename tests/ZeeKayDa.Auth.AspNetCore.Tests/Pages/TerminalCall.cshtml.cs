using System.Security.Claims;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using ZeeKayDa.Auth.AspNetCore.Interaction;
using ZeeKayDa.Auth.Authorization;

namespace ZeeKayDa.Auth.AspNetCore.Tests.Pages;

/// <summary>
/// A host login page written as Razor Pages, its handlers ending after a terminal call the way a
/// host would write them. Antiforgery is off so a test can post without rendering the form first.
/// </summary>
[IgnoreAntiforgeryToken]
public sealed class TerminalCallModel(ILoginInteraction login) : PageModel
{
    public const string RenderedText = "Rendered by the host page.";
    public const string HijackTarget = "https://attacker.example.net/collect";

    public Task OnPostSignInAsync() => login.SignInAsync(TestUser(), AuthenticationMethods.Password);

    public Task OnPostCancelAsync() => login.DenyAsync();

    /// <summary>Returns a result of its own after the terminal call, which must not reach the browser.</summary>
    public async Task<IActionResult> OnPostSignInThenRedirectAsync()
    {
        await login.SignInAsync(TestUser(), AuthenticationMethods.Password);
        return Redirect(HijackTarget);
    }

    /// <summary>Makes no terminal call, so the page renders as it would in any host.</summary>
    public IActionResult OnPostRender() => Page();

    internal static ClaimsPrincipal TestUser() =>
        new(new ClaimsIdentity([new Claim("sub", "user-1")], "test"));
}
