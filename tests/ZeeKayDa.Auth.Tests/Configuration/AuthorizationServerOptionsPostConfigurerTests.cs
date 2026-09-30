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

    // ── CorsOrigins ──────────────────────────────────────────────────────────────────────────────

    [Fact]
    public void PostConfigure_keeps_CorsOrigins_exactly_as_the_host_configured_them()
    {
        var options = new AuthorizationServerOptions { Issuer = "https://auth.example.com" };
        options.CorsOrigins.Add("HTTPS://APP.EXAMPLE.COM/");
        options.CorsOrigins.Add("https://app.example.com");
        options.CorsOrigins.Add("not-a-uri");

        PostConfigure(options);

        options.CorsOrigins.Should().Equal("HTTPS://APP.EXAMPLE.COM/", "https://app.example.com", "not-a-uri");
    }

    [Fact]
    public void PostConfigure_freezes_the_collection_as_read_only()
    {
        var options = new AuthorizationServerOptions { Issuer = "https://auth.example.com" };
        options.CorsOrigins.Add("https://app.example.com");

        PostConfigure(options);

        options.CorsOrigins.IsReadOnly.Should().BeTrue();
        var act = () => options.CorsOrigins.Add("https://admin.example.com");
        act.Should().Throw<NotSupportedException>();
    }

    [Fact]
    public void PostConfigure_freezes_empty_collection()
    {
        var options = new AuthorizationServerOptions { Issuer = "https://auth.example.com" };

        PostConfigure(options);

        options.CorsOrigins.IsReadOnly.Should().BeTrue();
    }

    [Fact]
    public void PostConfigure_is_idempotent_on_repeated_calls()
    {
        var options = new AuthorizationServerOptions { Issuer = "https://auth.example.com" };
        options.CorsOrigins.Add("HTTPS://APP.EXAMPLE.COM");
        PostConfigure(options);
        PostConfigure(options);

        options.CorsOrigins.Should().Equal("HTTPS://APP.EXAMPLE.COM");
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
