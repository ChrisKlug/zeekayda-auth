using ZeeKayDa.Auth.Scopes;

namespace ZeeKayDa.Auth.Tests.Scopes;

public sealed class StandardScopesTests
{
    private static readonly string[] ProfileClaims =
    [
        "name",
        "family_name",
        "given_name",
        "middle_name",
        "nickname",
        "preferred_username",
        "profile",
        "picture",
        "website",
        "gender",
        "birthdate",
        "zoneinfo",
        "locale",
        "updated_at",
    ];

    [Fact]
    public void OpenId_is_configured_as_expected()
    {
        StandardScopes.OpenId.Name.Should().Be("openid");
        StandardScopes.OpenId.IsDiscoverable.Should().BeTrue();
        StandardScopes.OpenId.IdTokenClaims.Should().Equal("sub");
        StandardScopes.OpenId.UserInfoClaims.Should().Equal("sub");
    }

    [Fact]
    public void Profile_is_configured_as_expected()
    {
        StandardScopes.Profile.Name.Should().Be("profile");
        StandardScopes.Profile.IsDiscoverable.Should().BeTrue();
        StandardScopes.Profile.IdTokenClaims.Should().BeEmpty();
        StandardScopes.Profile.UserInfoClaims.Should().Equal(ProfileClaims);
    }

    [Fact]
    public void Email_is_configured_as_expected()
    {
        StandardScopes.Email.Name.Should().Be("email");
        StandardScopes.Email.IsDiscoverable.Should().BeTrue();
        StandardScopes.Email.IdTokenClaims.Should().BeEmpty();
        StandardScopes.Email.UserInfoClaims.Should().Equal("email", "email_verified");
    }

    [Fact]
    public void Phone_is_configured_as_expected()
    {
        StandardScopes.Phone.Name.Should().Be("phone");
        StandardScopes.Phone.IsDiscoverable.Should().BeTrue();
        StandardScopes.Phone.IdTokenClaims.Should().BeEmpty();
        StandardScopes.Phone.UserInfoClaims.Should().Equal("phone_number", "phone_number_verified");
    }

    [Fact]
    public void Address_is_configured_as_expected()
    {
        StandardScopes.Address.Name.Should().Be("address");
        StandardScopes.Address.IsDiscoverable.Should().BeTrue();
        StandardScopes.Address.IdTokenClaims.Should().BeEmpty();
        StandardScopes.Address.UserInfoClaims.Should().Equal("address");
    }

    [Fact]
    public void No_standard_scope_unlocks_an_access_token_claim_or_names_an_audience()
    {
        foreach (var scope in StandardScopes.All)
        {
            scope.AccessTokenClaims.Should().BeEmpty($"{scope.Name} is an identity scope");
            scope.Audience.Should().BeNull($"{scope.Name}'s audience is the issuer");
        }
    }

    [Fact]
    public void Only_openid_puts_a_claim_in_the_ID_token_because_5_4_routes_the_rest_to_userinfo()
    {
        foreach (var scope in StandardScopes.All.Where(scope => scope.Name != StandardScopes.OpenId.Name))
        {
            scope.IdTokenClaims.Should().BeEmpty($"OpenID Connect Core §5.4 returns {scope.Name}'s claims from userinfo");
            scope.UserInfoClaims.Should().NotBeEmpty($"{scope.Name} unlocks its claims at userinfo");
        }
    }

    [Fact]
    public void A_host_can_add_a_scopes_claims_to_the_ID_token_with_a_with_expression()
    {
        var wide = StandardScopes.Email with { IdTokenClaims = StandardScopes.Email.UserInfoClaims };

        wide.IdTokenClaims.Should().Equal("email", "email_verified");
        wide.UserInfoClaims.Should().Equal("email", "email_verified");
        StandardScopes.Email.IdTokenClaims.Should().BeEmpty("the template is untouched");
    }

    [Fact]
    public void Definitions_are_immutable_and_stable()
    {
        StandardScopes.OpenId.Should().BeSameAs(StandardScopes.OpenId);
        StandardScopes.Profile.Should().BeSameAs(StandardScopes.Profile);

        var userInfoClaims = (ICollection<string>)StandardScopes.Profile.UserInfoClaims;
        userInfoClaims.IsReadOnly.Should().BeTrue();

        var allScopes = (ICollection<ScopeDefinition>)StandardScopes.All;
        allScopes.IsReadOnly.Should().BeTrue();
    }
}
