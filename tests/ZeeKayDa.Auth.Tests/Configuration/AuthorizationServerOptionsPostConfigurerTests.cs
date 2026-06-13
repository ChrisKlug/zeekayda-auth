using ZeeKayDa.Auth.Configuration;

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
}
