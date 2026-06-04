using Microsoft.Extensions.Options;
using ZeeKayDa.Auth.Configuration;
using ZeeKayDa.Auth.Discovery;
using ZeeKayDa.Auth.Scopes;

namespace ZeeKayDa.Auth.Tests.Configuration;

public sealed class AuthorizationServerOptionsValidatorTests
{
    private const string ClientCredentialsRequiresNonNoneTokenAuthMethodMessage =
        "GrantTypesSupported includes 'client_credentials', which requires confidential clients. " +
        "TokenEndpoint.AuthMethodsSupported must contain at least one method other than 'none'. " +
        "See RFC 6749 §4.4 and OAuth 2.0 Security BCP §2.6 (RFC 9700).";

    private static ValidateOptionsResult Validate(
        AuthorizationServerOptions options,
        IScopeRepository? scopeRepository = null)
        => new AuthorizationServerOptionsValidator(
            scopeRepository ?? new InMemoryScopeRepository([StandardScopes.OpenId]))
        .Validate(null, options);

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

    [Fact]
    public void Validate_IssuerWithUserInfo_Fails()
    {
        var result = Validate(new AuthorizationServerOptions
        {
            Issuer = "https://user:pass@auth.example.com",
        });

        result.Failed.Should().BeTrue();
        result.FailureMessage.Should().Contain("user information");
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

    [Fact]
    public void Validate_HttpIssuerWithFlagForNonLoopback_Fails()
    {
        var result = Validate(new AuthorizationServerOptions
        {
            Issuer = "http://auth.example.com",
            AllowInsecureIssuer = true,
        });

        result.Failed.Should().BeTrue();
        result.FailureMessage.Should().Contain("loopback");
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

    [Fact]
    public void Validate_IssuerWithUppercaseHost_FailsWithCanonicalSuggestion()
    {
        var result = Validate(new AuthorizationServerOptions
        {
            Issuer = "https://AUTH.example.com",
        });

        result.Failed.Should().BeTrue();
        result.FailureMessage.Should().Contain("is not canonical");
        result.FailureMessage.Should().Contain("https://auth.example.com");
    }

    [Fact]
    public void Validate_IssuerWithUppercaseScheme_FailsWithCanonicalSuggestion()
    {
        var result = Validate(new AuthorizationServerOptions
        {
            Issuer = "HTTPS://auth.example.com",
        });

        result.Failed.Should().BeTrue();
        result.FailureMessage.Should().Contain("is not canonical");
        result.FailureMessage.Should().Contain("https://auth.example.com");
    }

    [Fact]
    public void Validate_IssuerWithExplicitDefaultHttpsPort_FailsWithCanonicalSuggestion()
    {
        var result = Validate(new AuthorizationServerOptions
        {
            Issuer = "https://auth.example.com:443",
        });

        result.Failed.Should().BeTrue();
        result.FailureMessage.Should().Contain("is not canonical");
        result.FailureMessage.Should().Contain("https://auth.example.com");
    }

    [Fact]
    public void Validate_IssuerWithExplicitDefaultHttpPortForLoopback_FailsWithCanonicalSuggestion()
    {
        var result = Validate(new AuthorizationServerOptions
        {
            Issuer = "http://localhost:80",
            AllowInsecureIssuer = true,
        });

        result.Failed.Should().BeTrue();
        result.FailureMessage.Should().Contain("is not canonical");
        result.FailureMessage.Should().Contain("http://localhost");
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
            Response = { TypesSupported = null! },
        });

        result.Failed.Should().BeTrue();
        result.FailureMessage.Should().Contain("Response.TypesSupported");
    }

    [Fact]
    public void Validate_EmptyResponseTypesSupported_Fails()
    {
        var result = Validate(new AuthorizationServerOptions
        {
            Issuer = "https://auth.example.com",
            Response = { TypesSupported = [] },
        });

        result.Failed.Should().BeTrue();
        result.FailureMessage.Should().Contain("Response.TypesSupported");
    }

    [Fact]
    public void Validate_NullResponseModesSupported_Fails()
    {
        var result = Validate(new AuthorizationServerOptions
        {
            Issuer = "https://auth.example.com",
            Response = { ModesSupported = null! },
        });

        result.Failed.Should().BeTrue();
        result.FailureMessage.Should().Contain("Response.ModesSupported");
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
    public void Validate_OutOfRangeGrantTypesSupported_Fails()
    {
        var result = Validate(new AuthorizationServerOptions
        {
            Issuer = "https://auth.example.com",
            GrantTypesSupported = [(GrantType)9999],
        });

        result.Failed.Should().BeTrue();
        result.FailureMessage.Should().Contain("GrantTypesSupported");
        result.FailureMessage.Should().Contain(nameof(GrantType));
    }

    [Fact]
    public void Validate_NullTokenAuthMethodsSupported_Fails()
    {
        var result = Validate(new AuthorizationServerOptions
        {
            Issuer = "https://auth.example.com",
            TokenEndpoint = { AuthMethodsSupported = null! },
        });

        result.Failed.Should().BeTrue();
        result.FailureMessage.Should().Contain("TokenEndpoint.AuthMethodsSupported");
        result.FailureMessage.Should().Contain("null or empty");
    }

    [Fact]
    public void Validate_EmptyTokenAuthMethodsSupported_Fails()
    {
        var result = Validate(new AuthorizationServerOptions
        {
            Issuer = "https://auth.example.com",
            TokenEndpoint = { AuthMethodsSupported = [] },
        });

        result.Failed.Should().BeTrue();
        result.FailureMessage.Should().Contain("TokenEndpoint.AuthMethodsSupported");
        result.FailureMessage.Should().Contain("null or empty");
    }

    [Fact]
    public void Validate_OutOfRangeTokenAuthMethodsSupported_Fails()
    {
        var result = Validate(new AuthorizationServerOptions
        {
            Issuer = "https://auth.example.com",
            TokenEndpoint = { AuthMethodsSupported = [(TokenEndpointAuthMethod)9999] },
        });

        result.Failed.Should().BeTrue();
        result.FailureMessage.Should().Contain("TokenEndpoint.AuthMethodsSupported");
        result.FailureMessage.Should().Contain(nameof(TokenEndpointAuthMethod));
    }

    [Fact]
    public void Validate_NoneOnlyAuthMethodWithoutClientCredentials_Succeeds()
    {
        var result = Validate(new AuthorizationServerOptions
        {
            Issuer = "https://auth.example.com",
            GrantTypesSupported = [GrantType.AuthorizationCode],
            TokenEndpoint = { AuthMethodsSupported = [TokenEndpointAuthMethod.None] },
        });

        result.Succeeded.Should().BeTrue();
    }

    [Fact]
    public void Validate_ClientCredentialsWithOnlyNoneAuthMethod_Fails()
    {
        var result = Validate(new AuthorizationServerOptions
        {
            Issuer = "https://auth.example.com",
            GrantTypesSupported = [GrantType.ClientCredentials],
            TokenEndpoint = { AuthMethodsSupported = [TokenEndpointAuthMethod.None] },
        });

        result.Failed.Should().BeTrue();
        result.FailureMessage.Should().Be(ClientCredentialsRequiresNonNoneTokenAuthMethodMessage);
    }

    [Fact]
    public void Validate_ClientCredentialsMixedWithAuthorizationCodeAndOnlyNoneAuthMethod_Fails()
    {
        var result = Validate(new AuthorizationServerOptions
        {
            Issuer = "https://auth.example.com",
            GrantTypesSupported = [GrantType.AuthorizationCode, GrantType.ClientCredentials],
            TokenEndpoint = { AuthMethodsSupported = [TokenEndpointAuthMethod.None] },
        });

        result.Failed.Should().BeTrue();
        result.FailureMessage.Should().Be(ClientCredentialsRequiresNonNoneTokenAuthMethodMessage);
    }

    [Fact]
    public void Validate_ClientCredentialsWithNonAuthMethod_Succeeds()
    {
        var result = Validate(new AuthorizationServerOptions
        {
            Issuer = "https://auth.example.com",
            GrantTypesSupported = [GrantType.ClientCredentials],
            TokenEndpoint = { AuthMethodsSupported = [TokenEndpointAuthMethod.ClientSecretBasic] },
        });

        result.Succeeded.Should().BeTrue();
    }

    [Fact]
    public void Validate_ClientCredentialsWithNoneAndOtherAuthMethods_Succeeds()
    {
        var result = Validate(new AuthorizationServerOptions
        {
            Issuer = "https://auth.example.com",
            GrantTypesSupported = [GrantType.ClientCredentials],
            TokenEndpoint = { AuthMethodsSupported = [TokenEndpointAuthMethod.None, TokenEndpointAuthMethod.ClientSecretBasic] },
        });

        result.Succeeded.Should().BeTrue();
    }

    [Fact]
    public void Validate_NoneAuthMethodWithoutAuthorizationCodeGrant_Succeeds()
    {
        var result = Validate(new AuthorizationServerOptions
        {
            Issuer = "https://auth.example.com",
            GrantTypesSupported = [GrantType.RefreshToken],
            TokenEndpoint = { AuthMethodsSupported = [TokenEndpointAuthMethod.None] },
        });

        result.Succeeded.Should().BeTrue();
    }

    [Fact]
    public void Validate_NoneAuthMethodWithAuthorizationCodeGrant_Succeeds()
    {
        var result = Validate(new AuthorizationServerOptions
        {
            Issuer = "https://auth.example.com",
            GrantTypesSupported = [GrantType.AuthorizationCode],
            TokenEndpoint = { AuthMethodsSupported = [TokenEndpointAuthMethod.None] },
        });

        result.Succeeded.Should().BeTrue();
    }

    [Fact]
    public void Validate_NoneAuthMethodWithMultipleGrantsIncludingAuthorizationCode_Succeeds()
    {
        var result = Validate(new AuthorizationServerOptions
        {
            Issuer = "https://auth.example.com",
            GrantTypesSupported = [GrantType.AuthorizationCode, GrantType.RefreshToken],
            TokenEndpoint = { AuthMethodsSupported = [TokenEndpointAuthMethod.None] },
        });

        result.Succeeded.Should().BeTrue();
    }

    [Fact]
    public void Validate_NullIdTokenSigningAlgValuesSupported_Fails()
    {
        var result = Validate(new AuthorizationServerOptions
        {
            Issuer = "https://auth.example.com",
            IdToken = { SigningAlgValuesSupported = null! },
        });

        result.Failed.Should().BeTrue();
        result.FailureMessage.Should().Contain("IdToken.SigningAlgValuesSupported");
    }

    [Fact]
    public void Validate_EmptyIdTokenSigningAlgValuesSupported_Fails()
    {
        var result = Validate(new AuthorizationServerOptions
        {
            Issuer = "https://auth.example.com",
            IdToken = { SigningAlgValuesSupported = [] },
        });

        result.Failed.Should().BeTrue();
        result.FailureMessage.Should().Contain("IdToken.SigningAlgValuesSupported");
    }

    // ── AuthorizationEndpoint.CodeChallengeMethodsSupported ───────────────────────────────────────

    [Fact]
    public void Validate_NullCodeChallengeMethodsSupported_Succeeds()
    {
        var result = Validate(new AuthorizationServerOptions
        {
            Issuer = "https://auth.example.com",
            AuthorizationEndpoint = { CodeChallengeMethodsSupported = null },
        });

        result.Succeeded.Should().BeTrue();
    }

    [Fact]
    public void Validate_CodeChallengeMethodsSupportedWithS256_Succeeds()
    {
        var result = Validate(new AuthorizationServerOptions
        {
            Issuer = "https://auth.example.com",
            AuthorizationEndpoint = { CodeChallengeMethodsSupported = [CodeChallengeMethod.S256] },
        });

        result.Succeeded.Should().BeTrue();
    }

    [Fact]
    public void Validate_EmptyCodeChallengeMethodsSupported_Fails()
    {
        var result = Validate(new AuthorizationServerOptions
        {
            Issuer = "https://auth.example.com",
            AuthorizationEndpoint = { CodeChallengeMethodsSupported = [] },
        });

        result.Failed.Should().BeTrue();
        result.FailureMessage.Should().Contain("AuthorizationEndpoint.CodeChallengeMethodsSupported");
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

    [Fact]
    public void Validate_OpenIdScopePresent_Succeeds()
    {
        var result = Validate(
            new AuthorizationServerOptions
            {
                Issuer = "https://auth.example.com",
            },
            new InMemoryScopeRepository([StandardScopes.OpenId]));

        result.Succeeded.Should().BeTrue();
    }

    [Fact]
    public void Validate_DefaultInMemoryScopesWithOpenId_Succeeds()
    {
        var result = Validate(
            new AuthorizationServerOptions
            {
                Issuer = "https://auth.example.com",
            },
            new InMemoryScopeRepository(StandardScopes.All));

        result.Succeeded.Should().BeTrue();
    }

    [Fact]
    public void Validate_OpenIdScopeMissing_Fails()
    {
        var result = Validate(
            new AuthorizationServerOptions
            {
                Issuer = "https://auth.example.com",
            },
            new InMemoryScopeRepository([StandardScopes.Profile]));

        result.Failed.Should().BeTrue();
        result.FailureMessage.Should().Contain(StandardScopes.OpenId.Name);
    }

    [Fact]
    public void Validate_CustomRepositoryWithoutOpenId_Fails()
    {
        var result = Validate(
            new AuthorizationServerOptions
            {
                Issuer = "https://auth.example.com",
            },
            new CustomScopeRepositoryWithoutOpenId());

        result.Failed.Should().BeTrue();
        result.FailureMessage.Should().Contain(StandardScopes.OpenId.Name);
    }

    // ── Endpoint URI overrides ────────────────────────────────────────────────────────────────────

    [Theory]
    [InlineData("AuthorizationEndpoint.Uri", "not-a-uri")]
    [InlineData("TokenEndpoint.Uri", "not-a-uri")]
    [InlineData("JwksEndpoint.Uri", "not-a-uri")]
    public void Validate_EndpointOverrideNotAbsoluteUri_Fails(string propertyPath, string value)
    {
        var options = new AuthorizationServerOptions { Issuer = "https://auth.example.com" };
        SetGroupProperty(options, propertyPath, value);

        var result = Validate(options);

        result.Failed.Should().BeTrue();
        result.FailureMessage.Should().Contain("Uri");
    }

    [Theory]
    [InlineData("AuthorizationEndpoint.Uri", "http://auth.example.com/connect/authorize")]
    [InlineData("TokenEndpoint.Uri", "http://auth.example.com/connect/token")]
    [InlineData("JwksEndpoint.Uri", "http://auth.example.com/connect/jwks")]
    public void Validate_EndpointOverrideHttpWithoutFlag_Fails(string propertyPath, string value)
    {
        var options = new AuthorizationServerOptions { Issuer = "https://auth.example.com" };
        SetGroupProperty(options, propertyPath, value);

        var result = Validate(options);

        result.Failed.Should().BeTrue();
        result.FailureMessage.Should().Contain("HTTPS");
    }

    [Theory]
    [InlineData("AuthorizationEndpoint.Uri", "https://auth.example.com/connect/authorize")]
    [InlineData("TokenEndpoint.Uri", "https://auth.example.com/connect/token")]
    [InlineData("JwksEndpoint.Uri", "https://auth.example.com/connect/jwks")]
    public void Validate_EndpointOverrideHttps_Succeeds(string propertyPath, string value)
    {
        var options = new AuthorizationServerOptions { Issuer = "https://auth.example.com" };
        SetGroupProperty(options, propertyPath, value);

        var result = Validate(options);

        result.Succeeded.Should().BeTrue();
    }

    [Theory]
    [InlineData("AuthorizationEndpoint.Uri", "https://evil.example.com/connect/authorize")]
    [InlineData("TokenEndpoint.Uri", "https://evil.example.com/connect/token")]
    [InlineData("JwksEndpoint.Uri", "https://evil.example.com/connect/jwks")]
    public void Validate_EndpointOverrideDifferentAuthority_Fails(string propertyPath, string value)
    {
        var options = new AuthorizationServerOptions { Issuer = "https://auth.example.com" };
        SetGroupProperty(options, propertyPath, value);

        var result = Validate(options);

        result.Failed.Should().BeTrue();
        result.FailureMessage.Should().Contain("same authority");
    }

    [Theory]
    [InlineData("AuthorizationEndpoint.Uri", "https://auth.example.com:443/connect/authorize")]
    [InlineData("TokenEndpoint.Uri", "https://auth.example.com:443/connect/token")]
    [InlineData("JwksEndpoint.Uri", "https://auth.example.com:443/connect/jwks")]
    public void Validate_EndpointOverrideSameHostWithDefaultPort_Succeeds(string propertyPath, string value)
    {
        var options = new AuthorizationServerOptions { Issuer = "https://auth.example.com" };
        SetGroupProperty(options, propertyPath, value);

        var result = Validate(options);

        result.Succeeded.Should().BeTrue();
    }

    [Theory]
    [InlineData("AuthorizationEndpoint.Uri", "https://AUTH.example.com/connect/authorize")]
    [InlineData("TokenEndpoint.Uri", "https://AUTH.example.com/connect/token")]
    [InlineData("JwksEndpoint.Uri", "https://AUTH.example.com/connect/jwks")]
    public void Validate_EndpointOverrideSameAuthorityCaseInsensitiveHost_Succeeds(string propertyPath, string value)
    {
        var options = new AuthorizationServerOptions { Issuer = "https://auth.example.com" };
        SetGroupProperty(options, propertyPath, value);

        var result = Validate(options);

        result.Succeeded.Should().BeTrue();
    }

    [Theory]
    [InlineData("AuthorizationEndpoint.Uri", "https://auth.example.com:8443/connect/authorize")]
    [InlineData("TokenEndpoint.Uri", "https://auth.example.com:8443/connect/token")]
    [InlineData("JwksEndpoint.Uri", "https://auth.example.com:8443/connect/jwks")]
    public void Validate_EndpointOverrideDifferentPort_Fails(string propertyPath, string value)
    {
        var options = new AuthorizationServerOptions { Issuer = "https://auth.example.com" };
        SetGroupProperty(options, propertyPath, value);

        var result = Validate(options);

        result.Failed.Should().BeTrue();
        result.FailureMessage.Should().Contain("same authority");
    }

    [Theory]
    [InlineData("AuthorizationEndpoint.Uri", "https://user:pass@auth.example.com/connect/authorize")]
    [InlineData("TokenEndpoint.Uri", "https://user:pass@auth.example.com/connect/token")]
    [InlineData("JwksEndpoint.Uri", "https://user:pass@auth.example.com/connect/jwks")]
    public void Validate_EndpointOverrideWithUserInfo_Fails(string propertyPath, string value)
    {
        var options = new AuthorizationServerOptions { Issuer = "https://auth.example.com" };
        SetGroupProperty(options, propertyPath, value);

        var result = Validate(options);

        result.Failed.Should().BeTrue();
        result.FailureMessage.Should().Contain("user information");
    }

    [Theory]
    [InlineData("AuthorizationEndpoint.Uri", "http://auth.example.com/connect/authorize")]
    [InlineData("TokenEndpoint.Uri", "http://auth.example.com/connect/token")]
    [InlineData("JwksEndpoint.Uri", "http://auth.example.com/connect/jwks")]
    public void Validate_EndpointOverrideHttpWithFlagForNonLoopback_Fails(string propertyPath, string value)
    {
        var options = new AuthorizationServerOptions
        {
            Issuer = "https://auth.example.com",
            AllowInsecureIssuer = true,
        };
        SetGroupProperty(options, propertyPath, value);

        var result = Validate(options);

        result.Failed.Should().BeTrue();
        result.FailureMessage.Should().Contain("loopback");
    }

    [Theory]
    [InlineData("AuthorizationEndpoint.Uri", "https://auth.example.com/connect/authorize#fragment")]
    [InlineData("TokenEndpoint.Uri", "https://auth.example.com/connect/token#fragment")]
    public void Validate_EndpointWithFragment_Fails(string propertyPath, string value)
    {
        var options = new AuthorizationServerOptions { Issuer = "https://auth.example.com" };
        SetGroupProperty(options, propertyPath, value);

        var result = Validate(options);

        result.Failed.Should().BeTrue();
    }

    [Theory]
    // RFC 6749 §3.1 explicitly permits query components on the authorization endpoint.
    // RFC 6749 §3.2 does not prohibit them on the token endpoint.
    [InlineData("AuthorizationEndpoint.Uri", "https://auth.example.com/connect/authorize?foo=bar")]
    [InlineData("TokenEndpoint.Uri", "https://auth.example.com/connect/token?foo=bar")]
    public void Validate_EndpointWithQuery_Succeeds(string propertyPath, string value)
    {
        var options = new AuthorizationServerOptions { Issuer = "https://auth.example.com" };
        SetGroupProperty(options, propertyPath, value);

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
            JwksEndpoint = { Uri = value },
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
            DiscoveryDocument = { CacheMaxAgeSeconds = -1 },
        });

        result.Failed.Should().BeTrue();
        result.FailureMessage.Should().Contain("DiscoveryDocument.CacheMaxAgeSeconds");
    }

    // ── CorsOrigins — scheme validation ──────────────────────────────────────────────────────────

    [Fact]
    public void Validate_CorsOrigin_Https_Succeeds()
    {
        var options = new AuthorizationServerOptions { Issuer = "https://auth.example.com" };
        options.DiscoveryDocument.CorsOrigins.Add("https://app.example.com");

        var result = Validate(options);

        result.Succeeded.Should().BeTrue();
    }

    [Fact]
    public void Validate_CorsOrigin_HttpScheme_WithoutFlag_Fails()
    {
        var options = new AuthorizationServerOptions { Issuer = "https://auth.example.com" };
        options.DiscoveryDocument.CorsOrigins.Add("http://app.example.com");

        var result = Validate(options);

        result.Failed.Should().BeTrue();
        result.FailureMessage.Should().Contain("http://app.example.com");
    }

    [Fact]
    public void Validate_CorsOrigin_FtpScheme_Fails()
    {
        var options = new AuthorizationServerOptions { Issuer = "https://auth.example.com" };
        options.DiscoveryDocument.CorsOrigins.Add("ftp://files.example.com");

        var result = Validate(options);

        result.Failed.Should().BeTrue();
        result.FailureMessage.Should().Contain("ftp://files.example.com");
    }

    [Fact]
    public void Validate_CorsOrigin_HttpLoopback_WithFlag_Succeeds()
    {
        var options = new AuthorizationServerOptions
        {
            Issuer = "http://localhost",
            AllowInsecureIssuer = true,
        };
        options.DiscoveryDocument.CorsOrigins.Add("http://localhost:3000");

        var result = Validate(options);

        result.Succeeded.Should().BeTrue();
    }

    [Fact]
    public void Validate_CorsOrigin_HttpNonLoopback_WithFlag_Fails()
    {
        var options = new AuthorizationServerOptions
        {
            Issuer = "http://localhost",
            AllowInsecureIssuer = true,
        };
        options.DiscoveryDocument.CorsOrigins.Add("http://app.example.com");

        var result = Validate(options);

        result.Failed.Should().BeTrue();
        result.FailureMessage.Should().Contain("loopback");
    }

    [Fact]
    public void Validate_CorsOrigins_Canonicalized_AfterValidation()
    {
        var options = new AuthorizationServerOptions { Issuer = "https://auth.example.com" };
        options.DiscoveryDocument.CorsOrigins.Add("HTTPS://APP.EXAMPLE.COM");

        var result = Validate(options);

        result.Succeeded.Should().BeTrue();
        options.DiscoveryDocument.CorsOrigins.Should().ContainSingle()
            .Which.Should().Be("https://app.example.com");
    }

    [Fact]
    public void Validate_CorsOrigins_Deduplicated_AfterValidation()
    {
        var options = new AuthorizationServerOptions { Issuer = "https://auth.example.com" };
        options.DiscoveryDocument.CorsOrigins.Add("https://app.example.com");
        options.DiscoveryDocument.CorsOrigins.Add("HTTPS://APP.EXAMPLE.COM");

        var result = Validate(options);

        result.Succeeded.Should().BeTrue();
        options.DiscoveryDocument.CorsOrigins.Should().ContainSingle();
    }

    [Fact]
    public void Validate_CorsOrigins_BecomeReadOnly_AfterValidation()
    {
        var options = new AuthorizationServerOptions { Issuer = "https://auth.example.com" };
        options.DiscoveryDocument.CorsOrigins.Add("https://app.example.com");

        var result = Validate(options);

        result.Succeeded.Should().BeTrue();
        options.DiscoveryDocument.CorsOrigins.IsReadOnly.Should().BeTrue();
        var act = () => options.DiscoveryDocument.CorsOrigins.Add("https://admin.example.com");
        act.Should().Throw<NotSupportedException>();
    }

    [Theory]
    [InlineData(null, "A null value is not a valid CORS origin.")]
    [InlineData("", "An empty string is not a valid CORS origin.")]
    [InlineData("https://app.example.com\r\nx:y", "must not contain CR or LF characters")]
    [InlineData("null", "'null' is not a valid CORS origin.")]
    [InlineData("https://*.example.com", "must not contain wildcard characters")]
    [InlineData("not-a-uri", "is not a valid absolute URI")]
    [InlineData("https://user@app.example.com", "must not contain user information")]
    [InlineData("https://app.example.com?x=1", "must not contain a query component")]
    [InlineData("https://app.example.com#frag", "must not contain a fragment component")]
    [InlineData("https://app.example.com/path", "must not contain a path component")]
    public void Validate_CorsOrigins_InvalidValues_FailWithSpecificReason(string? origin, string expectedMessageFragment)
    {
        var options = new AuthorizationServerOptions { Issuer = "https://auth.example.com" };
        options.DiscoveryDocument.CorsOrigins.Add(origin!);

        var result = Validate(options);

        result.Failed.Should().BeTrue();
        result.FailureMessage.Should().Contain(expectedMessageFragment);
    }

    // ── SecurityHeaders — enum validation ────────────────────────────────────────────────────────

    [Fact]
    public void Validate_ReferrerPolicy_OutOfRange_Fails()
    {
        var options = new AuthorizationServerOptions
        {
            Issuer = "https://auth.example.com",
            SecurityHeaders = { ReferrerPolicy = (ReferrerPolicy)9999 },
        };

        var result = Validate(options);

        result.Failed.Should().BeTrue();
        result.FailureMessage.Should().Contain("ReferrerPolicy");
    }

    [Fact]
    public void Validate_CrossOriginResourcePolicy_OutOfRange_Fails()
    {
        var options = new AuthorizationServerOptions
        {
            Issuer = "https://auth.example.com",
            SecurityHeaders = { CrossOriginResourcePolicy = (CrossOriginResourcePolicy)9999 },
        };

        var result = Validate(options);

        result.Failed.Should().BeTrue();
        result.FailureMessage.Should().Contain("CrossOriginResourcePolicy");
    }

    private static void SetGroupProperty(AuthorizationServerOptions options, string propertyPath, string value)
    {
        var parts = propertyPath.Split('.');
        var group = typeof(AuthorizationServerOptions).GetProperty(parts[0])!.GetValue(options)!;
        var prop = group.GetType().GetProperty(parts[1])!;
        prop.SetValue(group, value);
    }

    private sealed class CustomScopeRepositoryWithoutOpenId : IScopeRepository
    {
        public ValueTask<IReadOnlyCollection<ScopeDefinition>> GetScopesAsync(CancellationToken cancellationToken = default)
            => ValueTask.FromResult<IReadOnlyCollection<ScopeDefinition>>([StandardScopes.Profile]);
    }
}
