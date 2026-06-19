using Microsoft.Extensions.Options;
using ZeeKayDa.Auth.Authorization;
using ZeeKayDa.Auth.Configuration;
using ZeeKayDa.Auth.Security;
using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.Tests.Configuration;

public sealed class AuthorizationServerOptionsValidatorTests
{
    private const string ClientCredentialsRequiresNonNoneTokenAuthMethodMessage =
        "GrantTypesSupported includes 'client_credentials', which requires confidential clients. " +
        "TokenEndpoint.AuthMethodsSupported must contain at least one method other than 'none'. " +
        "See RFC 6749 §4.4 and OAuth 2.0 Security BCP §2.6 (RFC 9700).";

    private static ValidateOptionsResult Validate(AuthorizationServerOptions options)
        => new AuthorizationServerOptionsValidator().Validate(null, options);

    // ── Issuer presence ──────────────────────────────────────────────────────────────────────────

    [Fact]
    public void Validate_fails_when_Issuer_is_null()
    {
        var result = Validate(new AuthorizationServerOptions { Issuer = null });

        result.Failed.Should().BeTrue();
        result.FailureMessage.Should().Contain("Issuer");
    }

    [Fact]
    public void Validate_fails_when_Issuer_is_empty()
    {
        var result = Validate(new AuthorizationServerOptions { Issuer = "" });

        result.Failed.Should().BeTrue();
        result.FailureMessage.Should().Contain("Issuer");
    }

    [Fact]
    public void Validate_fails_when_Issuer_is_whitespace()
    {
        var result = Validate(new AuthorizationServerOptions { Issuer = "   " });

        result.Failed.Should().BeTrue();
        result.FailureMessage.Should().Contain("Issuer");
    }

    // ── URI validity ─────────────────────────────────────────────────────────────────────────────

    [Fact]
    public void Validate_fails_for_relative_URI_Issuer()
    {
        // A path-only string has no scheme — Uri.TryCreate returns false for UriKind.Absolute.
        var result = Validate(new AuthorizationServerOptions { Issuer = "relative/path" });

        result.Failed.Should().BeTrue();
        result.FailureMessage.Should().Contain("not a valid absolute URI");
    }

    [Fact]
    public void Validate_fails_for_plain_string_Issuer()
    {
        var result = Validate(new AuthorizationServerOptions { Issuer = "not-a-uri-at-all" });

        result.Failed.Should().BeTrue();
    }

    // ── Query component ───────────────────────────────────────────────────────────────────────────

    [Fact]
    public void Validate_fails_when_Issuer_has_query_string()
    {
        var result = Validate(new AuthorizationServerOptions
        {
            Issuer = "https://auth.example.com?tenant=1",
        });

        result.Failed.Should().BeTrue();
        result.FailureMessage.Should().Contain("query");
    }

    [Fact]
    public void Validate_fails_when_Issuer_has_path_and_query_string()
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
    public void Validate_fails_when_Issuer_has_fragment()
    {
        var result = Validate(new AuthorizationServerOptions
        {
            Issuer = "https://auth.example.com#section",
        });

        result.Failed.Should().BeTrue();
        result.FailureMessage.Should().Contain("fragment");
    }

    [Fact]
    public void Validate_fails_when_Issuer_has_user_info()
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
    public void Validate_fails_for_HTTP_Issuer_without_AllowInsecureIssuer_flag()
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
    public void Validate_succeeds_for_HTTP_Issuer_with_AllowInsecureIssuer_flag()
    {
        var result = Validate(new AuthorizationServerOptions
        {
            Issuer = "http://localhost:5000",
            AllowInsecureIssuer = true,
        });

        result.Succeeded.Should().BeTrue();
    }

    [Fact]
    public void Validate_fails_for_HTTP_non_loopback_Issuer_with_AllowInsecureIssuer_flag()
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
    public void Validate_fails_when_Issuer_has_trailing_slash_on_path(string issuer, bool allowInsecure = false)
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
    public void Validate_succeeds_for_HTTPS_root_Issuer_with_no_path()
    {
        // https://auth.example.com has AbsolutePath "/" — must not be treated as trailing slash
        var result = Validate(new AuthorizationServerOptions { Issuer = "https://auth.example.com" });
        result.Succeeded.Should().BeTrue();
    }

    [Fact]
    public void Validate_succeeds_for_HTTPS_root_Issuer_with_trailing_slash()
    {
        // NormalizeRootIssuer strips the trailing "/" on a root issuer before the canonical
        // comparison, so "https://auth.example.com/" is treated as equivalent to the canonical form.
        var result = Validate(new AuthorizationServerOptions { Issuer = "https://auth.example.com/" });
        result.Succeeded.Should().BeTrue();
    }

    [Fact]
    public void Validate_succeeds_for_Issuer_with_non_default_HTTPS_port()
    {
        // Port 8443 ≠ 443, so isDefaultPort = false and the port is preserved in the canonical
        // form, making the input identical to the canonical — no "not canonical" failure.
        var result = Validate(new AuthorizationServerOptions { Issuer = "https://auth.example.com:8443" });
        result.Succeeded.Should().BeTrue();
    }

    [Fact]
    public void Validate_fails_with_canonical_suggestion_when_Issuer_host_is_uppercase()
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
    public void Validate_fails_with_canonical_suggestion_when_Issuer_scheme_is_uppercase()
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
    public void Validate_fails_with_canonical_suggestion_when_Issuer_has_explicit_default_HTTPS_port()
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
    public void Validate_fails_with_canonical_suggestion_when_Issuer_has_explicit_default_HTTP_port_for_loopback()
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
    public void Validate_fails_for_non_HTTP_or_HTTPS_scheme_Issuer_even_with_AllowInsecureIssuer_flag(string issuer)
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
    public void Validate_fails_when_ResponseTypesSupported_is_null()
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
    public void Validate_fails_when_ResponseTypesSupported_is_empty()
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
    public void Validate_fails_when_ResponseModesSupported_is_null()
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
    public void Validate_fails_when_GrantTypesSupported_is_null()
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
    public void Validate_fails_when_GrantTypesSupported_contains_out_of_range_value()
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
    public void Validate_fails_when_TokenEndpointAuthMethodsSupported_is_null()
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
    public void Validate_fails_when_TokenEndpointAuthMethodsSupported_is_empty()
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
    public void Validate_fails_when_TokenEndpointAuthMethodsSupported_contains_empty_string()
    {
        var result = Validate(new AuthorizationServerOptions
        {
            Issuer = "https://auth.example.com",
            TokenEndpoint = { AuthMethodsSupported = [""] },
        });

        result.Failed.Should().BeTrue();
        result.FailureMessage.Should().Contain("TokenEndpoint.AuthMethodsSupported");
    }

    [Fact]
    public void Validate_fails_when_TokenEndpointAuthMethodsSupported_contains_whitespace_only_string()
    {
        var result = Validate(new AuthorizationServerOptions
        {
            Issuer = "https://auth.example.com",
            TokenEndpoint = { AuthMethodsSupported = ["   "] },
        });

        result.Failed.Should().BeTrue();
        result.FailureMessage.Should().Contain("TokenEndpoint.AuthMethodsSupported");
    }

    [Fact]
    public void Validate_fails_when_TokenEndpointAuthMethodsSupported_contains_leading_whitespace()
    {
        var result = Validate(new AuthorizationServerOptions
        {
            Issuer = "https://auth.example.com",
            TokenEndpoint = { AuthMethodsSupported = [" client_secret_basic"] },
        });

        result.Failed.Should().BeTrue();
        result.FailureMessage.Should().Contain("TokenEndpoint.AuthMethodsSupported");
    }

    [Fact]
    public void Validate_fails_when_TokenEndpointAuthMethodsSupported_contains_control_character()
    {
        var result = Validate(new AuthorizationServerOptions
        {
            Issuer = "https://auth.example.com",
            TokenEndpoint = { AuthMethodsSupported = ["client\x00secret"] },
        });

        result.Failed.Should().BeTrue();
        result.FailureMessage.Should().Contain("TokenEndpoint.AuthMethodsSupported");
    }

    [Fact]
    public void Validate_succeeds_when_TokenEndpointAuthMethodsSupported_contains_custom_method_string()
    {
        var result = Validate(new AuthorizationServerOptions
        {
            Issuer = "https://auth.example.com",
            TokenEndpoint = { AuthMethodsSupported = ["tls_client_auth"] },
        });

        result.Succeeded.Should().BeTrue();
    }

    [Fact]
    public void Validate_succeeds_when_None_is_only_auth_method_and_no_client_credentials_grant()
    {
        var result = Validate(new AuthorizationServerOptions
        {
            Issuer = "https://auth.example.com",
            GrantTypesSupported = [GrantType.AuthorizationCode],
            TokenEndpoint = { AuthMethodsSupported = [TokenEndpointAuthMethods.None] },
        });

        result.Succeeded.Should().BeTrue();
    }

    [Fact]
    public void Validate_fails_when_ClientCredentials_grant_and_only_None_auth_method()
    {
        var result = Validate(new AuthorizationServerOptions
        {
            Issuer = "https://auth.example.com",
            GrantTypesSupported = [GrantType.ClientCredentials],
            TokenEndpoint = { AuthMethodsSupported = [TokenEndpointAuthMethods.None] },
        });

        result.Failed.Should().BeTrue();
        result.FailureMessage.Should().Be(ClientCredentialsRequiresNonNoneTokenAuthMethodMessage);
    }

    [Fact]
    public void Validate_fails_when_ClientCredentials_and_AuthorizationCode_grants_and_only_None_auth_method()
    {
        var result = Validate(new AuthorizationServerOptions
        {
            Issuer = "https://auth.example.com",
            GrantTypesSupported = [GrantType.AuthorizationCode, GrantType.ClientCredentials],
            TokenEndpoint = { AuthMethodsSupported = [TokenEndpointAuthMethods.None] },
        });

        result.Failed.Should().BeTrue();
        result.FailureMessage.Should().Be(ClientCredentialsRequiresNonNoneTokenAuthMethodMessage);
    }

    [Fact]
    public void Validate_succeeds_when_ClientCredentials_grant_and_non_None_auth_method()
    {
        var result = Validate(new AuthorizationServerOptions
        {
            Issuer = "https://auth.example.com",
            GrantTypesSupported = [GrantType.ClientCredentials],
            TokenEndpoint = { AuthMethodsSupported = [TokenEndpointAuthMethods.ClientSecretBasic] },
        });

        result.Succeeded.Should().BeTrue();
    }

    [Fact]
    public void Validate_succeeds_when_ClientCredentials_grant_and_None_plus_other_auth_methods()
    {
        var result = Validate(new AuthorizationServerOptions
        {
            Issuer = "https://auth.example.com",
            GrantTypesSupported = [GrantType.ClientCredentials],
            TokenEndpoint = { AuthMethodsSupported = [TokenEndpointAuthMethods.None, TokenEndpointAuthMethods.ClientSecretBasic] },
        });

        result.Succeeded.Should().BeTrue();
    }

    [Fact]
    public void Validate_succeeds_when_None_auth_method_and_no_AuthorizationCode_grant()
    {
        var result = Validate(new AuthorizationServerOptions
        {
            Issuer = "https://auth.example.com",
            GrantTypesSupported = [GrantType.RefreshToken],
            TokenEndpoint = { AuthMethodsSupported = [TokenEndpointAuthMethods.None] },
        });

        result.Succeeded.Should().BeTrue();
    }

    [Fact]
    public void Validate_succeeds_when_None_auth_method_and_AuthorizationCode_grant()
    {
        var result = Validate(new AuthorizationServerOptions
        {
            Issuer = "https://auth.example.com",
            GrantTypesSupported = [GrantType.AuthorizationCode],
            TokenEndpoint = { AuthMethodsSupported = [TokenEndpointAuthMethods.None] },
        });

        result.Succeeded.Should().BeTrue();
    }

    [Fact]
    public void Validate_succeeds_when_None_auth_method_and_multiple_grants_including_AuthorizationCode()
    {
        var result = Validate(new AuthorizationServerOptions
        {
            Issuer = "https://auth.example.com",
            GrantTypesSupported = [GrantType.AuthorizationCode, GrantType.RefreshToken],
            TokenEndpoint = { AuthMethodsSupported = [TokenEndpointAuthMethods.None] },
        });

        result.Succeeded.Should().BeTrue();
    }

    [Fact]
    public void Validate_fails_when_IdTokenSigningAlgValuesSupported_is_null()
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
    public void Validate_fails_when_IdTokenSigningAlgValuesSupported_is_empty()
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
    public void Validate_succeeds_when_CodeChallengeMethodsSupported_is_null()
    {
        var result = Validate(new AuthorizationServerOptions
        {
            Issuer = "https://auth.example.com",
            AuthorizationEndpoint = { CodeChallengeMethodsSupported = null },
        });

        result.Succeeded.Should().BeTrue();
    }

    [Fact]
    public void Validate_succeeds_when_CodeChallengeMethodsSupported_contains_S256()
    {
        var result = Validate(new AuthorizationServerOptions
        {
            Issuer = "https://auth.example.com",
            AuthorizationEndpoint = { CodeChallengeMethodsSupported = [CodeChallengeMethod.S256] },
        });

        result.Succeeded.Should().BeTrue();
    }

    [Fact]
    public void Validate_fails_when_CodeChallengeMethodsSupported_is_empty()
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
    public void Validate_succeeds_for_valid_HTTPS_Issuer()
    {
        var result = Validate(new AuthorizationServerOptions
        {
            Issuer = "https://auth.example.com",
        });

        result.Succeeded.Should().BeTrue();
    }

    [Fact]
    public void Validate_succeeds_for_valid_HTTPS_Issuer_with_path()
    {
        var result = Validate(new AuthorizationServerOptions
        {
            Issuer = "https://auth.example.com/tenant1",
        });

        result.Succeeded.Should().BeTrue();
    }

    // ── Endpoint URI overrides ────────────────────────────────────────────────────────────────────

    [Theory]
    [InlineData("AuthorizationEndpoint.Uri", "not-a-uri")]
    [InlineData("TokenEndpoint.Uri", "not-a-uri")]
    [InlineData("JwksEndpoint.Uri", "not-a-uri")]
    public void Validate_fails_when_endpoint_override_is_not_an_absolute_URI(string propertyPath, string value)
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
    public void Validate_fails_for_HTTP_endpoint_override_without_AllowInsecureIssuer_flag(string propertyPath, string value)
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
    public void Validate_succeeds_for_HTTPS_endpoint_override(string propertyPath, string value)
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
    public void Validate_fails_when_endpoint_override_has_different_authority(string propertyPath, string value)
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
    public void Validate_succeeds_when_endpoint_override_has_same_host_with_default_port(string propertyPath, string value)
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
    public void Validate_succeeds_when_endpoint_override_has_same_authority_with_case_insensitive_host(string propertyPath, string value)
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
    public void Validate_fails_when_endpoint_override_has_different_port(string propertyPath, string value)
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
    public void Validate_fails_when_endpoint_override_has_user_info(string propertyPath, string value)
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
    public void Validate_fails_for_HTTP_non_loopback_endpoint_override_with_AllowInsecureIssuer_flag(string propertyPath, string value)
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
    public void Validate_fails_when_endpoint_override_has_fragment(string propertyPath, string value)
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
    public void Validate_succeeds_when_endpoint_override_has_query(string propertyPath, string value)
    {
        var options = new AuthorizationServerOptions { Issuer = "https://auth.example.com" };
        SetGroupProperty(options, propertyPath, value);

        var result = Validate(options);

        result.Succeeded.Should().BeTrue();
    }

    [Theory]
    [InlineData("https://auth.example.com/connect/jwks?foo=bar")]
    [InlineData("https://auth.example.com/connect/jwks#fragment")]
    public void Validate_fails_when_JWKS_URI_override_has_query_or_fragment(string value)
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
    public void Validate_fails_for_negative_cache_max_age()
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
    public void Validate_succeeds_for_HTTPS_CORS_origin()
    {
        var options = new AuthorizationServerOptions { Issuer = "https://auth.example.com" };
        options.DiscoveryDocument.CorsOrigins.Add("https://app.example.com");

        var result = Validate(options);

        result.Succeeded.Should().BeTrue();
    }

    [Fact]
    public void Validate_fails_for_HTTP_CORS_origin_without_AllowInsecureIssuer_flag()
    {
        var options = new AuthorizationServerOptions { Issuer = "https://auth.example.com" };
        options.DiscoveryDocument.CorsOrigins.Add("http://app.example.com");

        var result = Validate(options);

        result.Failed.Should().BeTrue();
        result.FailureMessage.Should().Contain("http://app.example.com");
    }

    [Fact]
    public void Validate_fails_for_FTP_CORS_origin()
    {
        var options = new AuthorizationServerOptions { Issuer = "https://auth.example.com" };
        options.DiscoveryDocument.CorsOrigins.Add("ftp://files.example.com");

        var result = Validate(options);

        result.Failed.Should().BeTrue();
        result.FailureMessage.Should().Contain("ftp://files.example.com");
    }

    [Fact]
    public void Validate_succeeds_for_HTTP_loopback_CORS_origin_with_AllowInsecureIssuer_flag()
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
    public void Validate_fails_for_HTTP_non_loopback_CORS_origin_with_AllowInsecureIssuer_flag()
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
    public void Validate_fails_with_specific_reason_for_invalid_CORS_origins(string? origin, string expectedMessageFragment)
    {
        var options = new AuthorizationServerOptions { Issuer = "https://auth.example.com" };
        options.DiscoveryDocument.CorsOrigins.Add(origin!);

        var result = Validate(options);

        result.Failed.Should().BeTrue();
        result.FailureMessage.Should().Contain(expectedMessageFragment);
    }

    // ── SecurityHeaders — enum validation ────────────────────────────────────────────────────────

    [Fact]
    public void Validate_fails_when_ReferrerPolicy_is_out_of_range()
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
    public void Validate_fails_when_CrossOriginResourcePolicy_is_out_of_range()
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

    // ── Multi-error accumulation ──────────────────────────────────────────────────────────────────

    [Fact]
    public void Validate_accumulates_query_fragment_and_userinfo_errors_on_issuer_with_all_three_problems()
    {
        // https://user:pass@AUTH.example.com/path/?q=1#frag triggers:
        //   query, fragment, user-info, and canonicalization (uppercase host).
        var result = Validate(new AuthorizationServerOptions
        {
            Issuer = "https://user:pass@AUTH.example.com/path/?q=1#frag",
        });

        result.Failed.Should().BeTrue();
        result.FailureMessage.Should().Contain("query");
        result.FailureMessage.Should().Contain("fragment");
        result.FailureMessage.Should().Contain("user information");
        result.FailureMessage.Should().Contain("is not canonical");
    }

    [Fact]
    public void Validate_accumulates_multiple_TokenEndpointAuthMethods_invalid_entries()
    {
        // Three distinct invalid entries: whitespace-only, padded, control character.
        // The validator must accumulate one error per entry rather than stopping at the first.
        var result = Validate(new AuthorizationServerOptions
        {
            Issuer = "https://auth.example.com",
            TokenEndpoint = { AuthMethodsSupported = ["   ", " padded ", "ctrl\x00char"] },
        });

        result.Failed.Should().BeTrue();

        // Three errors must be present in the combined failure message.
        var message = result.FailureMessage!;
        var count = CountOccurrences(message, "TokenEndpoint.AuthMethodsSupported");
        count.Should().BeGreaterThanOrEqualTo(3,
            "each of the three invalid entries must produce a separate error message");
    }

    [Fact]
    public void Validate_accumulates_errors_across_different_groups()
    {
        // Bad issuer (trailing slash on path) combined with a null IdToken signing alg list.
        // Both errors must appear in a single result, proving cross-group accumulation.
        var result = Validate(new AuthorizationServerOptions
        {
            Issuer = "https://auth.example.com/tenant1/",
            IdToken = { SigningAlgValuesSupported = null! },
        });

        result.Failed.Should().BeTrue();
        result.FailureMessage.Should().Contain("trailing slash");
        result.FailureMessage.Should().Contain("IdToken.SigningAlgValuesSupported");
    }

    // ── ValidateEndpointUri — user-info branch ────────────────────────────────────────────────────

    [Fact]
    public void Validate_ValidateEndpointUri_returns_error_when_AuthorizationEndpoint_has_user_info()
    {
        var result = Validate(new AuthorizationServerOptions
        {
            Issuer = "https://auth.example.com",
            AuthorizationEndpoint = { Uri = "https://user:pass@auth.example.com/connect/authorize" },
        });

        result.Failed.Should().BeTrue();
        result.FailureMessage.Should().Contain("user information");
    }

    // ── ValidateEndpointUri — HTTP scheme branch (no AllowInsecureIssuer) ────────────────────────

    [Fact]
    public void Validate_ValidateEndpointUri_returns_error_when_AuthorizationEndpoint_uses_HTTP_without_AllowInsecureIssuer()
    {
        var result = Validate(new AuthorizationServerOptions
        {
            Issuer = "https://auth.example.com",
            AllowInsecureIssuer = false,
            AuthorizationEndpoint = { Uri = "http://auth.example.com/connect/authorize" },
        });

        result.Failed.Should().BeTrue();
        result.FailureMessage.Should().Contain("HTTPS");
    }

    // ── ValidateEndpointUri — HTTP non-loopback with AllowInsecureIssuer ─────────────────────────

    [Fact]
    public void Validate_ValidateEndpointUri_returns_error_when_AuthorizationEndpoint_uses_HTTP_non_loopback_with_AllowInsecureIssuer()
    {
        var result = Validate(new AuthorizationServerOptions
        {
            Issuer = "https://auth.example.com",
            AllowInsecureIssuer = true,
            AuthorizationEndpoint = { Uri = "http://auth.example.com/connect/authorize" },
        });

        result.Failed.Should().BeTrue();
        result.FailureMessage.Should().Contain("loopback");
    }

    // ── AuthorizationCodeLifetime defaults and validation ────────────────────────────────────────

    [Fact]
    public void AuthorizationCodeLifetime_defaults_to_60_seconds()
    {
        var options = new AuthorizationEndpointOptions();

        options.AuthorizationCodeLifetime.Should().Be(TimeSpan.FromSeconds(60));
    }

    [Fact]
    public void Validate_succeeds_when_AuthorizationCodeLifetime_is_minimum_valid_value()
    {
        var result = Validate(new AuthorizationServerOptions
        {
            Issuer = "https://auth.example.com",
            AuthorizationEndpoint = { AuthorizationCodeLifetime = TimeSpan.FromSeconds(1) },
        });

        result.Succeeded.Should().BeTrue();
    }

    [Fact]
    public void Validate_succeeds_when_AuthorizationCodeLifetime_is_exactly_600_seconds()
    {
        var result = Validate(new AuthorizationServerOptions
        {
            Issuer = "https://auth.example.com",
            AuthorizationEndpoint = { AuthorizationCodeLifetime = TimeSpan.FromSeconds(600) },
        });

        result.Succeeded.Should().BeTrue();
    }

    [Fact]
    public void Validate_fails_when_AuthorizationCodeLifetime_exceeds_600_seconds()
    {
        var result = Validate(new AuthorizationServerOptions
        {
            Issuer = "https://auth.example.com",
            AuthorizationEndpoint = { AuthorizationCodeLifetime = TimeSpan.FromSeconds(601) },
        });

        result.Failed.Should().BeTrue();
        result.FailureMessage.Should().Contain("600 seconds");
        result.FailureMessage.Should().Contain("RFC 9700 §2.1.1");
    }

    [Fact]
    public void Validate_fails_when_AuthorizationCodeLifetime_is_zero()
    {
        var result = Validate(new AuthorizationServerOptions
        {
            Issuer = "https://auth.example.com",
            AuthorizationEndpoint = { AuthorizationCodeLifetime = TimeSpan.Zero },
        });

        result.Failed.Should().BeTrue();
        result.FailureMessage.Should().Contain("greater than zero");
    }

    [Fact]
    public void Validate_fails_when_AuthorizationCodeLifetime_is_negative()
    {
        var result = Validate(new AuthorizationServerOptions
        {
            Issuer = "https://auth.example.com",
            AuthorizationEndpoint = { AuthorizationCodeLifetime = -TimeSpan.FromSeconds(1) },
        });

        result.Failed.Should().BeTrue();
        result.FailureMessage.Should().Contain("greater than zero");
    }

    // ── RefreshTokenLifetime defaults and validation ──────────────────────────────────────────────

    [Fact]
    public void RefreshTokenLifetime_defaults_to_14_days()
    {
        var options = new TokenEndpointOptions();

        options.RefreshTokenLifetime.Should().Be(TimeSpan.FromDays(14));
    }

    [Fact]
    public void Validate_succeeds_when_RefreshTokenLifetime_is_positive()
    {
        var result = Validate(new AuthorizationServerOptions
        {
            Issuer = "https://auth.example.com",
            TokenEndpoint = { RefreshTokenLifetime = TimeSpan.FromDays(1) },
        });

        result.Succeeded.Should().BeTrue();
    }

    [Fact]
    public void Validate_fails_when_RefreshTokenLifetime_is_zero()
    {
        var result = Validate(new AuthorizationServerOptions
        {
            Issuer = "https://auth.example.com",
            TokenEndpoint = { RefreshTokenLifetime = TimeSpan.Zero },
        });

        result.Failed.Should().BeTrue();
        result.FailureMessage.Should().Contain("greater than zero");
    }

    [Fact]
    public void Validate_fails_when_RefreshTokenLifetime_is_negative()
    {
        var result = Validate(new AuthorizationServerOptions
        {
            Issuer = "https://auth.example.com",
            TokenEndpoint = { RefreshTokenLifetime = -TimeSpan.FromDays(1) },
        });

        result.Failed.Should().BeTrue();
        result.FailureMessage.Should().Contain("greater than zero");
    }

    // ── Simultaneous authorization + token endpoint errors ───────────────────────────────────────

    [Fact]
    public void Validate_accumulates_authorization_endpoint_and_token_endpoint_errors_simultaneously()
    {
        // Both endpoints carry user-info so both ValidateEndpointUri calls return non-null,
        // proving both aeError and teError are accumulated in the same result.
        var result = Validate(new AuthorizationServerOptions
        {
            Issuer = "https://auth.example.com",
            AuthorizationEndpoint = { Uri = "https://user:pass@auth.example.com/connect/authorize" },
            TokenEndpoint =
            {
                Uri = "https://user:pass@auth.example.com/connect/token",
                AuthMethodsSupported = [TokenEndpointAuthMethods.ClientSecretBasic],
            },
        });

        result.Failed.Should().BeTrue();

        // Both endpoint URI values must appear in the combined failure message.
        result.FailureMessage.Should().Contain("https://user:pass@auth.example.com/connect/authorize");
        result.FailureMessage.Should().Contain("https://user:pass@auth.example.com/connect/token");
    }

    private static int CountOccurrences(string source, string substring)
    {
        var count = 0;
        var index = 0;
        while ((index = source.IndexOf(substring, index, StringComparison.Ordinal)) >= 0)
        {
            count++;
            index += substring.Length;
        }
        return count;
    }

    private static void SetGroupProperty(AuthorizationServerOptions options, string propertyPath, string value)
    {
        var parts = propertyPath.Split('.');
        var group = typeof(AuthorizationServerOptions).GetProperty(parts[0])!.GetValue(options)!;
        var prop = group.GetType().GetProperty(parts[1])!;
        prop.SetValue(group, value);
    }
}
