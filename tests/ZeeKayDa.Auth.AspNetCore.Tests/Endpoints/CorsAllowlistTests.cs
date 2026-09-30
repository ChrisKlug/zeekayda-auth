using Microsoft.Extensions.Options;
using ZeeKayDa.Auth.AspNetCore.Endpoints;

namespace ZeeKayDa.Auth.AspNetCore.Tests.Endpoints;

public sealed class CorsAllowlistTests
{
    private static CorsAllowlist Allowlist(params string[] origins)
    {
        var options = new AuthorizationServerOptions { Issuer = "https://auth.example.com" };
        foreach (var origin in origins)
            options.CorsOrigins.Add(origin);

        return new CorsAllowlist(Options.Create(options));
    }

    [Theory]
    [InlineData("HTTPS://APP.EXAMPLE.COM", "https://app.example.com")]
    [InlineData("https://app.example.com/", "https://app.example.com")]
    [InlineData("https://app.example.com:8443", "https://app.example.com:8443")]
    [InlineData("http://[::1]:5001", "http://[::1]:5001")]
    public void A_configured_origin_matches_in_its_canonical_form(string configured, string canonical)
    {
        var allowlist = Allowlist(configured);

        allowlist.TryMatch(canonical, out var matched).Should().BeTrue();
        matched.Should().Be(canonical);
    }

    [Fact]
    public void An_internationalized_host_matches_the_punycode_form_a_browser_sends()
    {
        var allowlist = Allowlist("https://bücher.example");

        allowlist.TryMatch("https://xn--bcher-kva.example", out var matched).Should().BeTrue();
        matched.Should().Be("https://xn--bcher-kva.example");
    }

    [Fact]
    public void A_request_origin_matches_case_insensitively_and_gets_the_listed_spelling_back()
    {
        var allowlist = Allowlist("https://app.example.com");

        allowlist.TryMatch("HTTPS://App.Example.Com", out var matched).Should().BeTrue();
        matched.Should().Be("https://app.example.com");
    }

    [Fact]
    public void An_origin_not_listed_does_not_match()
    {
        var allowlist = Allowlist("https://app.example.com");

        allowlist.TryMatch("https://evil.example.com", out _).Should().BeFalse();
    }

    [Fact]
    public void No_configured_origin_leaves_the_allowlist_empty()
    {
        Allowlist().IsEmpty.Should().BeTrue();
    }
}
