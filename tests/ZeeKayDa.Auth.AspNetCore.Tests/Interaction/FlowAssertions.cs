using System.Net;
using Microsoft.AspNetCore.WebUtilities;
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

    /// <summary>
    /// The response ended the authorization request with a code at <paramref name="redirectUri"/>
    /// — what a completed flow looks like from the client's side. Returns the code.
    /// </summary>
    public static string ShouldHaveIssuedCodeTo(this HttpResponseMessage response, string redirectUri, string because = "")
    {
        response.StatusCode.Should().Be(HttpStatusCode.Redirect, because);

        var location = response.Headers.Location!.OriginalString;
        new Uri(location).GetLeftPart(UriPartial.Path).Should().Be(redirectUri, because);

        var query = QueryHelpers.ParseQuery(location[location.IndexOf('?')..]);
        query.Should().NotContainKey("error", because);
        query.Should().ContainKey("code", because);

        return query["code"].Single()!;
    }

    /// <summary>
    /// The page had nothing to continue, and the framework answered with its own page — what a
    /// submission for an expired, completed or foreign interaction looks like on a host with no
    /// error page and a client with no <c>InitiateLoginUri</c>. No code, and no redirect anywhere.
    /// </summary>
    public static async Task ShouldHaveFoundNothingToContinueAsync(this HttpResponseMessage response, string because = "")
    {
        response.StatusCode.Should().Be(HttpStatusCode.BadRequest, because);
        (await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken))
            .Should().Contain(NothingToContinue.ErrorCode, because);
    }

    /// <summary>
    /// Whether a binding cookie's <c>Set-Cookie</c> header ends the binding: deleted outright, or
    /// rewritten as a tombstone that no longer carries the secret.
    /// </summary>
    public static bool IsRetiredBinding(string setCookie)
    {
        if (setCookie.Contains("expires=Thu, 01 Jan 1970", StringComparison.Ordinal))
            return true;

        var pair = setCookie.Split(';')[0];
        var value = pair[(pair.IndexOf('=') + 1)..];
        return value.Split('.') is [_, "", _];
    }
}
