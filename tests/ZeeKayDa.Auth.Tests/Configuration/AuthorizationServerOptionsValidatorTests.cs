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
        result.FailureMessage.Should().Contain("HTTPS");
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
}
