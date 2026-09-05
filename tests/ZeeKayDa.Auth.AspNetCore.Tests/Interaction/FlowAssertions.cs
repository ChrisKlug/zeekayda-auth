using System.Net;
using ZeeKayDa.Auth.AspNetCore.Interaction;

namespace ZeeKayDa.Auth.AspNetCore.Tests.Interaction;

/// <summary>
/// Assertions on where an authorization request went next, shared by the tests that drive the
/// flow through sign-in from several directions and only need to see it arrive at the next stage.
/// </summary>
internal static class FlowAssertions
{
    /// <summary>The consent page every test host maps, as <see cref="TestWebAppFactory"/> configures it.</summary>
    public const string ConsentPath = "/account/consent";

    /// <summary>
    /// The response continued the authorization request to the host's consent page, carrying
    /// the interaction identifier — what a completed sign-in for a client that requires consent
    /// looks like.
    /// </summary>
    public static void ShouldHaveReachedConsent(this HttpResponseMessage response, string because = "")
    {
        response.StatusCode.Should().Be(HttpStatusCode.Redirect, because);
        response.Headers.Location!.OriginalString
            .Should().StartWith($"{ConsentPath}?{InteractionHandoff.InteractionIdParameter}=", because);
    }
}
