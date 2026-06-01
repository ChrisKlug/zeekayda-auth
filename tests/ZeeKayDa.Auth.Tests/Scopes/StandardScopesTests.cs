using ZeeKayDa.Auth.Scopes;

namespace ZeeKayDa.Auth.Tests.Scopes;

public sealed class StandardScopesTests
{
    [Fact]
    public void OpenId_IsConfiguredAsExpected()
    {
        StandardScopes.OpenId.Name.Should().Be("openid");
        StandardScopes.OpenId.IsDiscoverable.Should().BeTrue();
        StandardScopes.OpenId.IdTokenClaims.Should().Equal("sub");
    }

    [Fact]
    public void Profile_IsConfiguredAsExpected()
    {
        StandardScopes.Profile.Name.Should().Be("profile");
        StandardScopes.Profile.IsDiscoverable.Should().BeTrue();
        StandardScopes.Profile.IdTokenClaims.Should().Equal(
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
            "updated_at");
    }

    [Fact]
    public void Email_IsConfiguredAsExpected()
    {
        StandardScopes.Email.Name.Should().Be("email");
        StandardScopes.Email.IsDiscoverable.Should().BeTrue();
        StandardScopes.Email.IdTokenClaims.Should().Equal("email", "email_verified");
    }

    [Fact]
    public void Phone_IsConfiguredAsExpected()
    {
        StandardScopes.Phone.Name.Should().Be("phone");
        StandardScopes.Phone.IsDiscoverable.Should().BeTrue();
        StandardScopes.Phone.IdTokenClaims.Should().Equal("phone_number", "phone_number_verified");
    }

    [Fact]
    public void Address_IsConfiguredAsExpected()
    {
        StandardScopes.Address.Name.Should().Be("address");
        StandardScopes.Address.IsDiscoverable.Should().BeTrue();
        StandardScopes.Address.IdTokenClaims.Should().Equal("address");
    }

    [Fact]
    public void Definitions_AreImmutableAndStable()
    {
        StandardScopes.OpenId.Should().BeSameAs(StandardScopes.OpenId);
        StandardScopes.Profile.Should().BeSameAs(StandardScopes.Profile);

        var idTokenClaims = (ICollection<string>)StandardScopes.Profile.IdTokenClaims;
        idTokenClaims.IsReadOnly.Should().BeTrue();

        var allScopes = (ICollection<ScopeDefinition>)StandardScopes.All;
        allScopes.IsReadOnly.Should().BeTrue();
    }
}
