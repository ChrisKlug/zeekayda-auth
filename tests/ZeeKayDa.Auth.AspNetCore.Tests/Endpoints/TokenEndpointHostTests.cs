using System.Net;
using System.Text.Json;
using ZeeKayDa.Auth.Stores;

namespace ZeeKayDa.Auth.AspNetCore.Tests.Endpoints;

/// <summary>
/// The parts of the token endpoint that only a real host can answer: that <c>/connect/token</c>
/// is registered for POST only (a wrong method never reaches the handler at all), and that
/// <c>AllowAnonymous</c> keeps it reachable under a host-wide fallback authorization policy. The
/// handler's own behaviour — client authentication, PKCE, code redemption, issuance — is covered
/// host-free in <see cref="TokenEndpointTests"/>.
/// </summary>
public sealed class TokenEndpointHostTests(DefaultHostFixture host, FallbackPolicyHostFixture fallback)
    : IClassFixture<DefaultHostFixture>,
      IClassFixture<FallbackPolicyHostFixture>
{
    private const string TokenPath = "/connect/token";

    private static CancellationToken Cancellation => TestContext.Current.CancellationToken;

    [Fact]
    public async Task The_token_endpoint_answers_POST_only()
    {
        var response = await host.Client.GetAsync(TokenPath, Cancellation);

        response.StatusCode.Should().Be(HttpStatusCode.MethodNotAllowed);
    }

    [Fact]
    public async Task The_token_endpoint_is_reachable_under_a_host_fallback_authorization_policy()
    {
        var client = fallback.Client;
        using var form = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["grant_type"] = "authorization_code",
            ["code"] = StoreKeyGenerator.Generate(),
            ["redirect_uri"] = "https://test.example.com/callback",
            ["client_id"] = "test-client",
            ["code_verifier"] = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
        });

        var canary = await client.GetAsync("/host-route", Cancellation);
        var response = await client.PostAsync(TokenPath, form, Cancellation);

        canary.StatusCode.Should().Be(HttpStatusCode.Unauthorized, "the fallback policy is in force on the host's own routes");
        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);
        var body = JsonDocument.Parse(await response.Content.ReadAsStringAsync(Cancellation)).RootElement;
        body.GetProperty("error").GetString().Should().Be(
            "invalid_grant", "the code does not exist, but the endpoint answered rather than being challenged by the host's own fallback policy");
    }
}
