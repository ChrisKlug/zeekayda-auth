using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.Tests.Tokens;

public sealed class AdvertisedAuthMethodsTests
{
    private static readonly string[] _secretMethods =
        [TokenEndpointAuthMethods.ClientSecretPost, TokenEndpointAuthMethods.ClientSecretBasic];

    [Fact]
    public void With_no_filter_every_performable_method_and_none_is_advertised_in_ordinal_order()
    {
        var advertised = new AdvertisedAuthMethods(_secretMethods, filter: null);

        advertised.Methods.Should().Equal(
            TokenEndpointAuthMethods.ClientSecretBasic, TokenEndpointAuthMethods.ClientSecretPost, TokenEndpointAuthMethods.None);
        advertised.Unperformable.Should().BeEmpty();
    }

    [Fact]
    public void The_filter_narrows_and_reports_the_entries_nothing_performs()
    {
        var advertised = new AdvertisedAuthMethods(
            _secretMethods, filter: [TokenEndpointAuthMethods.ClientSecretBasic, "private_key_jwt", "private_key_jwt"]);

        advertised.Methods.Should().Equal(TokenEndpointAuthMethods.ClientSecretBasic);
        advertised.Unperformable.Should().Equal("private_key_jwt");
        advertised.Contains("private_key_jwt").Should().BeFalse("a filter can never add a method");
    }

    [Fact]
    public void Contains_compares_ordinally()
    {
        var advertised = new AdvertisedAuthMethods(_secretMethods, filter: null);

        advertised.Contains(TokenEndpointAuthMethods.ClientSecretBasic).Should().BeTrue();
        advertised.Contains("Client_Secret_Basic").Should().BeFalse();
    }

    [Fact]
    public void A_malformed_declared_method_is_never_advertised()
    {
        var advertised = new AdvertisedAuthMethods([" client_secret_basic", null!, ""], filter: null);

        advertised.Methods.Should().Equal(TokenEndpointAuthMethods.None);
    }

    [Fact]
    public void Methods_cannot_be_cast_back_to_a_mutable_collection()
    {
        var advertised = new AdvertisedAuthMethods(_secretMethods, filter: null);

        advertised.Methods.Should().NotBeAssignableTo<string[]>();
        ((ICollection<string>)advertised.Methods).IsReadOnly.Should().BeTrue(
            "discovery publishes this instance, and the token endpoint checks the set it was built from");
    }
}
