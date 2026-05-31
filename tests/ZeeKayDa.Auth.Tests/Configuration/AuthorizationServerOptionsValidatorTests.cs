using Microsoft.Extensions.Options;
using ZeeKayDa.Auth.Configuration;
using ZeeKayDa.Auth.Discovery;

namespace ZeeKayDa.Auth.Tests.Configuration;

public sealed class AuthorizationServerOptionsValidatorTests
{
    private static ValidateOptionsResult Validate(AuthorizationServerOptions options)
        => new AuthorizationServerOptionsValidator().Validate(null, options);

    // ── Issuer presence ──────────────────────────────────────────────────────────────────────────

    [Fact]
    public void Validate_NullIssuer_Fails()
    {
        var result = Validate(new AuthorizationServerOptions { Issuer = null });

        result.Failed.Should().BeTrue();
        result.FailureMessage.Should().Contain("Issuer");
    }

    [Fact]
    public void Validate_EmptyIssuer_Fails()
    {
        var result = Validate(new AuthorizationServerOptions { Issuer = "" });

        result.Failed.Should().BeTrue();
        result.FailureMessage.Should().Contain("Issuer");
    }

    [Fact]
    public void Validate_WhitespaceIssuer_Fails()
    {
        var result = Validate(new AuthorizationServerOptions { Issuer = "   " });

        result.Failed.Should().BeTrue();
        result.FailureMessage.Should().Contain("Issuer");
    }

    // ── URI validity ─────────────────────────────────────────────────────────────────────────────

    [Fact]
    public void Validate_RelativeUri_Fails()
    {
        // A path-only string has no scheme — Uri.TryCreate returns false for UriKind.Absolute.
        var result = Validate(new AuthorizationServerOptions { Issuer = "relative/path" });

        result.Failed.Should().BeTrue();
        result.FailureMessage.Should().Contain("not a valid absolute URI");
    }

    [Fact]
    public void Validate_PlainString_Fails()
    {
        var result = Validate(new AuthorizationServerOptions { Issuer = "not-a-uri-at-all" });

        result.Failed.Should().BeTrue();
    }

    // ── Query component ───────────────────────────────────────────────────────────────────────────

    [Fact]
    public void Validate_IssuerWithQueryString_Fails()
    {
        var result = Validate(new AuthorizationServerOptions
        {
            Issuer = "https://auth.example.com?tenant=1",
        });

        result.Failed.Should().BeTrue();
        result.FailureMessage.Should().Contain("query");
    }

    [Fact]
    public void Validate_IssuerWithPathAndQueryString_Fails()
    {
        var result = Validate(new AuthorizationServerOptions
        {
            Issuer = "https://auth.example.com/tenant1?param=value",
        });

        result.Failed.Should().BeTrue();
        result.FailureMessage.Should().Contain("query");
    }

    // ── Fragment component ────────────────────────────────────────────────────────────────────────

    [Fact]
    public void Validate_IssuerWithFragment_Fails()
    {
        var result = Validate(new AuthorizationServerOptions
        {
            Issuer = "https://auth.example.com#section",
        });

        result.Failed.Should().BeTrue();
        result.FailureMessage.Should().Contain("fragment");
    }

    // ── HTTPS requirement ─────────────────────────────────────────────────────────────────────────

    [Fact]
    public void Validate_HttpIssuerWithoutFlag_Fails()
    {
        var result = Validate(new AuthorizationServerOptions
        {
            Issuer = "http://auth.example.com",
            AllowInsecureIssuer = false,
        });

        result.Failed.Should().BeTrue();
        result.FailureMessage.Should().Contain("scheme");
    }

    [Fact]
    public void Validate_HttpIssuerWithFlag_Succeeds()
    {
        var result = Validate(new AuthorizationServerOptions
        {
            Issuer = "http://localhost:5000",
            AllowInsecureIssuer = true,
        });

        result.Succeeded.Should().BeTrue();
    }

    [Theory]
    [InlineData("https://auth.example.com/tenant1/")]
    [InlineData("https://auth.example.com/a/b/c/")]
    [InlineData("http://localhost:5000/tenant1/", true)]
    public void Validate_IssuerWithTrailingSlashOnPath_Fails(string issuer, bool allowInsecure = false)
    {
        var result = Validate(new AuthorizationServerOptions
        {
            Issuer = issuer,
            AllowInsecureIssuer = allowInsecure,
        });

        result.Failed.Should().BeTrue();
        result.FailureMessage.Should().Contain("trailing slash");
    }

    [Fact]
    public void Validate_HttpsRootIssuerNoPath_Succeeds()
    {
        // https://auth.example.com has AbsolutePath "/" — must not be treated as trailing slash
        var result = Validate(new AuthorizationServerOptions { Issuer = "https://auth.example.com" });
        result.Succeeded.Should().BeTrue();
    }

    [Theory]
    [InlineData("ftp://localhost")]
    [InlineData("file:///tmp/auth")]
    [InlineData("custom://localhost")]
    public void Validate_NonHttpOrHttpsSchemeWithFlag_Fails(string issuer)
    {
        var result = Validate(new AuthorizationServerOptions
        {
            Issuer = issuer,
            AllowInsecureIssuer = true,
        });

        result.Failed.Should().BeTrue();
        result.FailureMessage.Should().Contain("scheme");
    }

    [Fact]
    public void Validate_NullResponseTypesSupported_Fails()
    {
        var result = Validate(new AuthorizationServerOptions
        {
            Issuer = "https://auth.example.com",
            ResponseTypesSupported = null!,
        });

        result.Failed.Should().BeTrue();
        result.FailureMessage.Should().Contain(nameof(AuthorizationServerOptions.ResponseTypesSupported));
    }

    [Fact]
    public void Validate_EmptyResponseTypesSupported_Fails()
    {
        var result = Validate(new AuthorizationServerOptions
        {
            Issuer = "https://auth.example.com",
            ResponseTypesSupported = [],
        });

        result.Failed.Should().BeTrue();
        result.FailureMessage.Should().Contain(nameof(AuthorizationServerOptions.ResponseTypesSupported));
    }

    [Fact]
    public void Validate_NullResponseModesSupported_Fails()
    {
        var result = Validate(new AuthorizationServerOptions
        {
            Issuer = "https://auth.example.com",
            ResponseModesSupported = null!,
        });

        result.Failed.Should().BeTrue();
        result.FailureMessage.Should().Contain(nameof(AuthorizationServerOptions.ResponseModesSupported));
    }

    [Fact]
    public void Validate_NullGrantTypesSupported_Fails()
    {
        var result = Validate(new AuthorizationServerOptions
        {
            Issuer = "https://auth.example.com",
            GrantTypesSupported = null!,
        });

        result.Failed.Should().BeTrue();
        result.FailureMessage.Should().Contain(nameof(AuthorizationServerOptions.GrantTypesSupported));
    }

    [Fact]
    public void Validate_NullTokenEndpointAuthMethodsSupported_Fails()
    {
        var result = Validate(new AuthorizationServerOptions
        {
            Issuer = "https://auth.example.com",
            TokenEndpointAuthMethodsSupported = null!,
        });

        result.Failed.Should().BeTrue();
        result.FailureMessage.Should().Contain(nameof(AuthorizationServerOptions.TokenEndpointAuthMethodsSupported));
    }

    [Fact]
    public void Validate_NullIdTokenSigningAlgValuesSupported_Fails()
    {
        var result = Validate(new AuthorizationServerOptions
        {
            Issuer = "https://auth.example.com",
            IdTokenSigningAlgValuesSupported = null!,
        });

        result.Failed.Should().BeTrue();
        result.FailureMessage.Should().Contain(nameof(AuthorizationServerOptions.IdTokenSigningAlgValuesSupported));
    }

    [Fact]
    public void Validate_EmptyIdTokenSigningAlgValuesSupported_Fails()
    {
        var result = Validate(new AuthorizationServerOptions
        {
            Issuer = "https://auth.example.com",
            IdTokenSigningAlgValuesSupported = [],
        });

        result.Failed.Should().BeTrue();
        result.FailureMessage.Should().Contain(nameof(AuthorizationServerOptions.IdTokenSigningAlgValuesSupported));
    }

    // ── Happy paths ───────────────────────────────────────────────────────────────────────────────

    [Fact]
    public void Validate_ValidHttpsIssuer_Succeeds()
    {
        var result = Validate(new AuthorizationServerOptions
        {
            Issuer = "https://auth.example.com",
        });

        result.Succeeded.Should().BeTrue();
    }

    [Fact]
    public void Validate_ValidHttpsIssuerWithPath_Succeeds()
    {
        var result = Validate(new AuthorizationServerOptions
        {
            Issuer = "https://auth.example.com/tenant1",
        });

        result.Succeeded.Should().BeTrue();
    }

    // ── Endpoint URI overrides ────────────────────────────────────────────────────────────────────

    [Theory]
    [InlineData(nameof(AuthorizationServerOptions.AuthorizationEndpoint), "not-a-uri")]
    [InlineData(nameof(AuthorizationServerOptions.TokenEndpoint), "not-a-uri")]
    [InlineData(nameof(AuthorizationServerOptions.JwksUri), "not-a-uri")]
    public void Validate_EndpointOverrideNotAbsoluteUri_Fails(string propertyName, string value)
    {
        var options = new AuthorizationServerOptions { Issuer = "https://auth.example.com" };
        SetEndpointProperty(options, propertyName, value);

        var result = Validate(options);

        result.Failed.Should().BeTrue();
        result.FailureMessage.Should().Contain(propertyName);
    }

    [Theory]
    [InlineData(nameof(AuthorizationServerOptions.AuthorizationEndpoint), "http://auth.example.com/connect/authorize")]
    [InlineData(nameof(AuthorizationServerOptions.TokenEndpoint), "http://auth.example.com/connect/token")]
    [InlineData(nameof(AuthorizationServerOptions.JwksUri), "http://auth.example.com/connect/jwks")]
    public void Validate_EndpointOverrideHttpWithoutFlag_Fails(string propertyName, string value)
    {
        var options = new AuthorizationServerOptions { Issuer = "https://auth.example.com" };
        SetEndpointProperty(options, propertyName, value);

        var result = Validate(options);

        result.Failed.Should().BeTrue();
        result.FailureMessage.Should().Contain("HTTPS");
    }

    [Theory]
    [InlineData(nameof(AuthorizationServerOptions.AuthorizationEndpoint), "https://auth.example.com/connect/authorize")]
    [InlineData(nameof(AuthorizationServerOptions.TokenEndpoint), "https://auth.example.com/connect/token")]
    [InlineData(nameof(AuthorizationServerOptions.JwksUri), "https://auth.example.com/connect/jwks")]
    public void Validate_EndpointOverrideHttps_Succeeds(string propertyName, string value)
    {
        var options = new AuthorizationServerOptions { Issuer = "https://auth.example.com" };
        SetEndpointProperty(options, propertyName, value);

        var result = Validate(options);

        result.Succeeded.Should().BeTrue();
    }

    [Theory]
    [InlineData("https://auth.example.com/connect/jwks?foo=bar")]
    [InlineData("https://auth.example.com/connect/jwks#fragment")]
    public void Validate_JwksUriWithQueryOrFragment_Fails(string value)
    {
        var result = Validate(new AuthorizationServerOptions
        {
            Issuer = "https://auth.example.com",
            JwksUri = value,
        });

        result.Failed.Should().BeTrue();
    }

    // ── Cache-Control max-age ─────────────────────────────────────────────────────────────────────

    [Fact]
    public void Validate_NegativeCacheMaxAge_Fails()
    {
        var result = Validate(new AuthorizationServerOptions
        {
            Issuer = "https://auth.example.com",
            DiscoveryDocumentCacheMaxAgeSeconds = -1,
        });

        result.Failed.Should().BeTrue();
        result.FailureMessage.Should().Contain(nameof(AuthorizationServerOptions.DiscoveryDocumentCacheMaxAgeSeconds));
    }

    private static void SetEndpointProperty(AuthorizationServerOptions options, string propertyName, string value)
    {
        var prop = typeof(AuthorizationServerOptions).GetProperty(propertyName)!;
        prop.SetValue(options, value);
    }
}
