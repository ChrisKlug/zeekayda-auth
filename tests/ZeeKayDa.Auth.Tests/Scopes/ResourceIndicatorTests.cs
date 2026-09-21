using ZeeKayDa.Auth.Scopes;

namespace ZeeKayDa.Auth.Tests.Scopes;

/// <summary>
/// RFC 8707 §2 resource indicators, checked as written rather than as <c>Uri</c> would rewrite
/// them: the original string is what a token's <c>aud</c> claim carries.
/// </summary>
public sealed class ResourceIndicatorTests
{
    [Theory]
    [InlineData("orders")]
    [InlineData("/orders")]
    [InlineData("C:\\orders")]
    [InlineData("https://orders.example.com/#")]
    public void An_audience_that_is_not_a_resource_indicator_is_rejected(string audience)
    {
        // ValidatedScopeCatalog refuses a repository serving one of these, so no grant ever
        // carries it; this pins the shape rule the catalog applies.
        ResourceIndicator.IsValid(audience).Should().BeFalse();
    }

    [Theory]
    [InlineData("https://orders.example.com/")]
    [InlineData("urn:example:orders")]
    [InlineData("https://orders.example.com/api?v=2")]
    [InlineData("https://orders.example.com")]
    [InlineData("https://orders.example.com/a%20b")]
    [InlineData("https://[::1]/api")]
    [InlineData("https://[2001:db8::1]:8443/orders")]
    public void A_resource_indicator_is_an_absolute_URI_with_its_scheme_written_and_no_fragment(string audience)
    {
        ResourceIndicator.IsValid(audience).Should().BeTrue();
    }

    [Theory]
    [InlineData("https://orders.example.com/orders v2")]
    [InlineData("https://orders.example.com/a\u00e9b")]
    [InlineData("https://orders.example.com/%zz")]
    [InlineData("https://orders.example.com/%a")]
    public void An_audience_Uri_would_silently_canonicalize_is_rejected(string audience)
    {
        // Uri.TryCreate parses all of these and rewrites them — a raw space becomes %20, a
        // non-ASCII letter becomes its percent-encoding, a bare % becomes %25. It is the original
        // string this framework writes into an access token's aud claim, so accepting on the parse
        // would put a value no conforming resource server can match into the token.
        ResourceIndicator.IsValid(audience).Should().BeFalse();
        Uri.TryCreate(audience, UriKind.Absolute, out _).Should().BeTrue("the parser accepts what RFC 3986 does not");
    }

    [Theory]
    [InlineData("https://orders.example.com/orders[beta]")]
    [InlineData("https://orders.example.com/api?filter=[x]")]
    [InlineData("urn:example:orders[beta]")]
    public void An_audience_with_a_bracket_outside_the_authority_is_rejected(string audience)
    {
        // RFC 3986 §3.2.2 permits a bracket only in an IP-literal host. Uri accepts one in a path,
        // and a resource server comparing against the percent-encoded form would not match the
        // value the token carries.
        ResourceIndicator.IsValid(audience).Should().BeFalse();
    }
}
