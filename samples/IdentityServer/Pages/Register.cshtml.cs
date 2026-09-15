using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using ZeeKayDa.Auth.Claims;
using ZeeKayDa.Auth.Samples.IdentityServer.Users;

namespace ZeeKayDa.Auth.Samples.IdentityServer.Pages;

/// <summary>
/// Adds a user to the in-memory store. Reached from the login page with its query string, and
/// sends the browser back there with it — so a sign-in in progress continues after registering.
/// </summary>
public sealed class RegisterModel(UserStore users) : PageModel
{
    [BindProperty]
    public string? Username { get; set; }

    [BindProperty]
    public string? Name { get; set; }

    [BindProperty]
    public string? Email { get; set; }

    public string? Error { get; private set; }

    public IActionResult OnPost(string? password)
    {
        if (string.IsNullOrWhiteSpace(Username) || string.IsNullOrEmpty(password))
        {
            Error = "A username and a password are required.";
            return Page();
        }

        List<ClaimRecord> claims = [new("preferred_username", Username)];
        if (!string.IsNullOrWhiteSpace(Name))
            claims.Add(new("name", Name));
        if (!string.IsNullOrWhiteSpace(Email))
            claims.Add(new("email", Email));

        if (!users.Add(Username, password, claims))
        {
            Error = "That username is taken.";
            return Page();
        }

        return Redirect("/login" + Request.QueryString);
    }
}
