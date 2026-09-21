using ZeeKayDa.Auth.Scopes;

namespace ZeeKayDa.Auth.Tests.Scopes;

public sealed class ScopeResolutionTests
{
    private static readonly ScopeDefinition OrdersRead = new() { Name = "orders.read", Audience = "https://orders.example.com/" };
    private static readonly ScopeDefinition OrdersWrite = new() { Name = "orders.write", Audience = "https://orders.example.com/" };
    private static readonly ScopeDefinition ReportsRead = new() { Name = "reports.read", Audience = "https://reports.example.com/" };

    [Fact]
    public void Every_named_scope_resolves_to_its_definition_in_request_order()
    {
        var found = ScopeResolution.TryResolve([OrdersRead, StandardScopes.OpenId], ["openid", "orders.read"], out var resolved, out var undefined);

        found.Should().BeTrue();
        resolved.Should().Equal(StandardScopes.OpenId, OrdersRead);
        undefined.Should().BeNull();
    }

    [Fact]
    public void A_name_with_no_definition_fails_and_is_named()
    {
        var found = ScopeResolution.TryResolve([StandardScopes.OpenId], ["openid", "missing"], out var resolved, out var undefined);

        found.Should().BeFalse();
        undefined.Should().Be("missing");
        resolved.Should().BeEmpty();
    }

    [Fact]
    public void Scope_names_resolve_ordinally()
    {
        var found = ScopeResolution.TryResolve([StandardScopes.OpenId], ["OpenID"], out _, out var undefined);

        found.Should().BeFalse();
        undefined.Should().Be("OpenID");
    }

    [Fact]
    public void Identity_scopes_alone_name_no_resource()
    {
        var ok = ScopeResolution.TryResolveAudience([StandardScopes.OpenId, StandardScopes.Profile], out var audience);

        ok.Should().BeTrue();
        audience.Should().BeNull();
    }

    [Fact]
    public void One_API_scope_names_its_audience()
    {
        var ok = ScopeResolution.TryResolveAudience([StandardScopes.OpenId, OrdersRead], out var audience);

        ok.Should().BeTrue();
        audience.Should().Be("https://orders.example.com/");
    }

    [Fact]
    public void Two_scopes_sharing_an_audience_string_are_one_API()
    {
        var ok = ScopeResolution.TryResolveAudience([OrdersRead, OrdersWrite], out var audience);

        ok.Should().BeTrue();
        audience.Should().Be("https://orders.example.com/");
    }

    [Fact]
    public void Two_distinct_audiences_cannot_be_resolved()
    {
        var ok = ScopeResolution.TryResolveAudience([StandardScopes.OpenId, OrdersRead, ReportsRead], out var audience);

        ok.Should().BeFalse();
        audience.Should().BeNull();
    }

    [Theory]
    [InlineData("orders")]
    [InlineData("/orders")]
    [InlineData("C:\\orders")]
    [InlineData("https://orders.example.com/#")]
    public void An_audience_that_is_not_a_resource_indicator_is_rejected(string audience)
    {
        // ValidatedScopeCatalog refuses a repository serving one of these, so no grant ever
        // carries it; this pins the shape rule the catalog applies.
        ScopeResolution.IsResourceIndicator(audience).Should().BeFalse();
    }

    [Theory]
    [InlineData("https://orders.example.com/")]
    [InlineData("urn:example:orders")]
    [InlineData("https://orders.example.com/api?v=2")]
    [InlineData("https://orders.example.com")]
    [InlineData("https://orders.example.com/a%20b")]
    public void A_resource_indicator_is_an_absolute_URI_with_its_scheme_written_and_no_fragment(string audience)
    {
        ScopeResolution.IsResourceIndicator(audience).Should().BeTrue();
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
        ScopeResolution.IsResourceIndicator(audience).Should().BeFalse();
        Uri.TryCreate(audience, UriKind.Absolute, out _).Should().BeTrue("the parser accepts what RFC 3986 does not");
    }

    [Fact]
    public void Audiences_are_compared_ordinally()
    {
        var upper = new ScopeDefinition { Name = "x", Audience = "https://ORDERS.example.com/" };

        var ok = ScopeResolution.TryResolveAudience([OrdersRead, upper], out _);

        ok.Should().BeFalse("RFC 7519 makes aud a case-sensitive string");
    }
}
