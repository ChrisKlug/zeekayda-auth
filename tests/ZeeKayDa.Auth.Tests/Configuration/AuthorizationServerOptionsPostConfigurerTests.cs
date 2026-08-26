using ZeeKayDa.Auth.Configuration;
using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.Tests.Configuration;

public sealed class AuthorizationServerOptionsPostConfigurerTests
{
    private static AuthorizationServerOptions PostConfigure(AuthorizationServerOptions options)
    {
        new AuthorizationServerOptionsPostConfigurer().PostConfigure(null, options);
        return options;
    }

    // ── Canonicalization ─────────────────────────────────────────────────────────────────────────

    [Fact]
    public void PostConfigure_lowercases_CORS_origin_scheme_and_host()
    {
        var options = new AuthorizationServerOptions { Issuer = "https://auth.example.com" };
        options.DiscoveryDocument.CorsOrigins.Add("HTTPS://APP.EXAMPLE.COM");

        PostConfigure(options);

        options.DiscoveryDocument.CorsOrigins.Should().ContainSingle()
            .Which.Should().Be("https://app.example.com");
    }

    [Fact]
    public void PostConfigure_canonicalizes_an_internationalized_host_to_its_punycode_form()
    {
        var options = new AuthorizationServerOptions { Issuer = "https://auth.example.com" };
        options.DiscoveryDocument.CorsOrigins.Add("https://bücher.example");

        PostConfigure(options);

        // Browsers serialize the Origin header in punycode, so the stored canonical entry must
        // be the A-label form or the allowlist entry could never match a real request.
        options.DiscoveryDocument.CorsOrigins.Should().ContainSingle()
            .Which.Should().Be("https://xn--bcher-kva.example");
    }

    [Fact]
    public void PostConfigure_preserves_the_brackets_of_an_ipv6_origin()
    {
        var options = new AuthorizationServerOptions { Issuer = "https://auth.example.com" };
        options.DiscoveryDocument.CorsOrigins.Add("http://[::1]:5001");

        PostConfigure(options);

        // Browsers serialize an IPv6 Origin with brackets; an entry stored without them could
        // never match a request.
        options.DiscoveryDocument.CorsOrigins.Should().ContainSingle()
            .Which.Should().Be("http://[::1]:5001");
    }

    [Fact]
    public void PostConfigure_leaves_an_origin_with_an_invalid_idn_host_as_is_for_the_validator()
    {
        var options = new AuthorizationServerOptions { Issuer = "https://auth.example.com" };
        options.DiscoveryDocument.CorsOrigins.Add("https://℀.example");

        PostConfigure(options);

        options.DiscoveryDocument.CorsOrigins.Should().ContainSingle()
            .Which.Should().Be("https://℀.example");
    }

    [Fact]
    public void PostConfigure_canonicalizes_and_freezes_the_jwks_CORS_allow_list()
    {
        var options = new AuthorizationServerOptions { Issuer = "https://auth.example.com" };
        options.JwksEndpoint.CorsOrigins.Add("HTTPS://APP.EXAMPLE.COM");

        PostConfigure(options);

        options.JwksEndpoint.CorsOrigins.Should().ContainSingle()
            .Which.Should().Be("https://app.example.com");
        options.JwksEndpoint.CorsOrigins.IsReadOnly.Should().BeTrue();
    }

    [Fact]
    public void PostConfigure_deduplicates_origins_case_insensitively()
    {
        var options = new AuthorizationServerOptions { Issuer = "https://auth.example.com" };
        options.DiscoveryDocument.CorsOrigins.Add("https://app.example.com");
        options.DiscoveryDocument.CorsOrigins.Add("HTTPS://APP.EXAMPLE.COM");

        PostConfigure(options);

        options.DiscoveryDocument.CorsOrigins.Should().ContainSingle();
    }

    [Fact]
    public void PostConfigure_freezes_the_collection_as_read_only()
    {
        var options = new AuthorizationServerOptions { Issuer = "https://auth.example.com" };
        options.DiscoveryDocument.CorsOrigins.Add("https://app.example.com");

        PostConfigure(options);

        options.DiscoveryDocument.CorsOrigins.IsReadOnly.Should().BeTrue();
        var act = () => options.DiscoveryDocument.CorsOrigins.Add("https://admin.example.com");
        act.Should().Throw<NotSupportedException>();
    }

    [Fact]
    public void PostConfigure_freezes_empty_collection()
    {
        var options = new AuthorizationServerOptions { Issuer = "https://auth.example.com" };

        PostConfigure(options);

        options.DiscoveryDocument.CorsOrigins.IsReadOnly.Should().BeTrue();
    }

    [Fact]
    public void PostConfigure_preserves_invalid_origins_so_validator_can_report_them()
    {
        var options = new AuthorizationServerOptions { Issuer = "https://auth.example.com" };
        options.DiscoveryDocument.CorsOrigins.Add("https://app.example.com");
        options.DiscoveryDocument.CorsOrigins.Add("not-a-uri");

        PostConfigure(options);

        options.DiscoveryDocument.CorsOrigins.Should().Contain("not-a-uri");
    }

    [Fact]
    public void PostConfigure_is_idempotent_on_repeated_calls()
    {
        var options = new AuthorizationServerOptions { Issuer = "https://auth.example.com" };
        options.DiscoveryDocument.CorsOrigins.Add("HTTPS://APP.EXAMPLE.COM");
        PostConfigure(options);
        PostConfigure(options); // second call on already-canonical frozen list

        options.DiscoveryDocument.CorsOrigins.Should().ContainSingle()
            .Which.Should().Be("https://app.example.com");
    }

    [Fact]
    public void PostConfigure_strips_trailing_slash_from_origin()
    {
        var options = new AuthorizationServerOptions { Issuer = "https://auth.example.com" };
        options.DiscoveryDocument.CorsOrigins.Add("https://app.example.com/");

        PostConfigure(options);

        options.DiscoveryDocument.CorsOrigins.Should().ContainSingle()
            .Which.Should().Be("https://app.example.com");
    }

    [Fact]
    public void PostConfigure_preserves_non_default_port_in_canonical_form()
    {
        var options = new AuthorizationServerOptions { Issuer = "https://auth.example.com" };
        options.DiscoveryDocument.CorsOrigins.Add("https://app.example.com:8443");

        PostConfigure(options);

        options.DiscoveryDocument.CorsOrigins.Should().ContainSingle()
            .Which.Should().Be("https://app.example.com:8443");
    }

    // ── IdToken.AdvertisedSigningAlgorithms ──────────────────────────────────────────────────────

    [Fact]
    public void PostConfigure_freezes_AdvertisedSigningAlgorithms()
    {
        // The discovery document reads this filter on every request; the startup checks that
        // reconcile it with the key set run exactly once.
        var options = new AuthorizationServerOptions { Issuer = "https://auth.example.com" };
        options.IdToken.AdvertisedSigningAlgorithms = [SigningAlgorithm.RS256];

        new AuthorizationServerOptionsPostConfigurer().PostConfigure(name: null, options);

        options.IdToken.AdvertisedSigningAlgorithms!.IsReadOnly.Should().BeTrue();
    }

    [Fact]
    public void PostConfigure_preserves_the_AdvertisedSigningAlgorithms_entries()
    {
        var options = new AuthorizationServerOptions { Issuer = "https://auth.example.com" };
        options.IdToken.AdvertisedSigningAlgorithms = [SigningAlgorithm.RS256, SigningAlgorithm.ES256];

        new AuthorizationServerOptionsPostConfigurer().PostConfigure(name: null, options);

        options.IdToken.AdvertisedSigningAlgorithms.Should().Equal(
            SigningAlgorithm.RS256, SigningAlgorithm.ES256);
    }

    [Fact]
    public void PostConfigure_leaves_a_null_AdvertisedSigningAlgorithms_null()
    {
        var options = new AuthorizationServerOptions { Issuer = "https://auth.example.com" };

        new AuthorizationServerOptionsPostConfigurer().PostConfigure(name: null, options);

        options.IdToken.AdvertisedSigningAlgorithms.Should().BeNull(
            "null is the default and means advertise the whole published key set");
    }
}
