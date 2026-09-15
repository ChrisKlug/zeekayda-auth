using Microsoft.AspNetCore.Mvc;
using ZeeKayDa.Auth.AspNetCore.Interaction;
using ZeeKayDa.Auth.AspNetCore.Tests.Pages;
using ZeeKayDa.Auth.Authorization;

namespace ZeeKayDa.Auth.AspNetCore.Tests.Interaction;

/// <summary>A host login page written as a controller, its actions ending after a terminal call.</summary>
[Route("mvc/login")]
public sealed class TerminalCallController(ILoginInteraction login) : ControllerBase
{
    [HttpPost("sign-in")]
    public Task SignIn() => login.SignInAsync(TerminalCallModel.TestUser(), AuthenticationMethods.Password);

    [HttpPost("cancel")]
    public Task Cancel() => login.DenyAsync();

    [HttpPost("challenge")]
    public Task ChallengeProvider() => login.ChallengeAsync("acme");
}
