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
        StandardScopes.Profile.IdTokenClaims.Should().Equal(ProfileClaims);
        StandardScopes.Profile.UserInfoClaims.Should().Equal(ProfileClaims);
    }

    [Fact]
    public void Email_is_configured_as_expected()
    {
        StandardScopes.Email.Name.Should().Be("email");
        StandardScopes.Email.IsDiscoverable.Should().BeTrue();
        StandardScopes.Email.IdTokenClaims.Should().Equal("email", "email_verified");
        StandardScopes.Email.UserInfoClaims.Should().Equal("email", "email_verified");
    }

    [Fact]
    public void Phone_is_configured_as_expected()
    {
        StandardScopes.Phone.Name.Should().Be("phone");
        StandardScopes.Phone.IsDiscoverable.Should().BeTrue();
        StandardScopes.Phone.IdTokenClaims.Should().Equal("phone_number", "phone_number_verified");
        StandardScopes.Phone.UserInfoClaims.Should().Equal("phone_number", "phone_number_verified");
    }

    [Fact]
    public void Address_is_configured_as_expected()
    {
        StandardScopes.Address.Name.Should().Be("address");
        StandardScopes.Address.IsDiscoverable.Should().BeTrue();
        StandardScopes.Address.IdTokenClaims.Should().Equal("address");
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
    public void A_host_can_trim_the_ID_token_list_to_the_specification_default_with_a_with_expression()
    {
        var slim = StandardScopes.Profile with { IdTokenClaims = ["name"] };

        slim.IdTokenClaims.Should().Equal("name");
        slim.UserInfoClaims.Should().Equal(ProfileClaims);
        StandardScopes.Profile.IdTokenClaims.Should().Equal(ProfileClaims, "the template is untouched");
    }

    [Fact]
    public void Definitions_are_immutable_and_stable()
    {
        StandardScopes.OpenId.Should().BeSameAs(StandardScopes.OpenId);
        StandardScopes.Profile.Should().BeSameAs(StandardScopes.Profile);

        var idTokenClaims = (ICollection<string>)StandardScopes.Profile.IdTokenClaims;
        idTokenClaims.IsReadOnly.Should().BeTrue();

        var allScopes = (ICollection<ScopeDefinition>)StandardScopes.All;
        allScopes.IsReadOnly.Should().BeTrue();
    }
}
