using ZeeKayDa.Auth.Clients;
using ZeeKayDa.Auth.Scopes;

namespace ZeeKayDa.Auth.Tests.Clients;

/// <summary>
/// An addition may not name a claim any scope unlocks in any destination: consent-bearing claims
/// arrive only through the scope the user can decline.
/// </summary>
public sealed class ClientClaimAdditionsTests
{
    private static readonly ScopeDefinition OrdersRead = new()
    {
        Name = "orders.read",
        AccessTokenClaims = ["role"],
        UserInfoClaims = ["customer_number"],
    };

    private static ClientRegistration Client(
        IReadOnlyCollection<string>? idToken = null,
        IReadOnlyCollection<string>? userInfo = null,
        IReadOnlyCollection<string>? accessToken = null) =>
        ClientRegistration.CreatePublic("app", ["https://app.example.com/cb"], [], ["openid"]) with
        {
            AdditionalIdTokenClaims = idToken ?? [],
            AdditionalUserInfoClaims = userInfo ?? [],
            AdditionalAccessTokenClaims = accessToken ?? [],
        };

    [Fact]
    public void An_addition_no_scope_unlocks_is_allowed()
    {
        var collision = ClientClaimAdditions.FindCollision(Client(idToken: ["tenant"], accessToken: ["tenant"]), StandardScopes.All);

        collision.Should().BeNull();
    }

    [Fact]
    public void An_addition_naming_a_consent_bearing_claim_is_refused()
    {
        var collision = ClientClaimAdditions.FindCollision(Client(idToken: ["email"]), StandardScopes.All);

        collision.Should().Be(new ClaimAdditionCollision("email", "email", nameof(IClientMetadata.AdditionalIdTokenClaims)));
    }

    [Fact]
    public void The_check_spans_destinations_so_an_access_token_addition_cannot_bypass_the_email_scope()
    {
        // No scope lists email for the access token; a per-destination check would let this through.
        var collision = ClientClaimAdditions.FindCollision(Client(accessToken: ["email"]), StandardScopes.All);

        collision.Should().NotBeNull();
        collision!.Value.Property.Should().Be(nameof(IClientMetadata.AdditionalAccessTokenClaims));
    }

    [Fact]
    public void A_userinfo_only_claim_counts_as_unlocked()
    {
        var collision = ClientClaimAdditions.FindCollision(Client(idToken: ["customer_number"]), [StandardScopes.OpenId, OrdersRead]);

        collision!.Value.Scope.Should().Be("orders.read");
    }

    [Fact]
    public void Claim_names_are_compared_ordinally()
    {
        var collision = ClientClaimAdditions.FindCollision(Client(idToken: ["Email"]), StandardScopes.All);

        collision.Should().BeNull("'Email' is not the claim the email scope unlocks");
    }

    [Fact]
    public void The_description_names_the_client_the_claim_the_scope_and_the_property()
    {
        var text = new ClaimAdditionCollision("email", "email", "AdditionalIdTokenClaims").Describe("app");

        text.Should().Contain("'app'").And.Contain("'email'").And.Contain("AdditionalIdTokenClaims");
    }
}
