using Microsoft.Extensions.Options;
using ZeeKayDa.Auth.Authorization;
using ZeeKayDa.Auth.Configuration;
using ZeeKayDa.Auth.Security;
using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.Tests.Configuration;

public sealed class AuthorizationServerOptionsValidatorTests
{
    private static IReadOnlyList<ZeeKayDaConfigurationFailure> Validate(AuthorizationServerOptions options)
    {
        try
        {
            ((IValidateOptions<AuthorizationServerOptions>)new AuthorizationServerOptionsValidator()).Validate(null, options);
            return [];
        }
        catch (ZeeKayDaConfigurationException exception)
        {
            return exception.AggregatedFailures;
        }
    }

    // ── Issuer presence ──────────────────────────────────────────────────────────────────────────

    [Fact]
    public void Validate_fails_when_Issuer_is_null()
    {
        var failures = Validate(new AuthorizationServerOptions { Issuer = null });

        failures.Should().ContainSingle(f => f.Code == "configuration.issuer.missing")
            .Which.Message.Should().Contain("Issuer");
    }

    [Fact]
    public void Validate_fails_when_Issuer_is_empty()
    {
        var failures = Validate(new AuthorizationServerOptions { Issuer = "" });

        failures.Should().ContainSingle(f => f.Code == "configuration.issuer.missing")
            .Which.Message.Should().Contain("Issuer");
    }

    [Fact]
    public void Validate_fails_when_Issuer_is_whitespace()
    {
        var failures = Validate(new AuthorizationServerOptions { Issuer = "   " });

        failures.Should().ContainSingle(f => f.Code == "configuration.issuer.missing")
            .Which.Message.Should().Contain("Issuer");
    }

    // ── URI validity ─────────────────────────────────────────────────────────────────────────────

    [Fact]
    public void Validate_fails_for_relative_URI_Issuer()
    {
        // A path-only string has no scheme — Uri.TryCreate returns false for UriKind.Absolute.
        var failures = Validate(new AuthorizationServerOptions { Issuer = "relative/path" });

        failures.Should().ContainSingle(f => f.Code == "configuration.issuer.invalid")
            .Which.Message.Should().Contain("not a valid absolute URI");
    }

    [Fact]
    public void Validate_fails_for_plain_string_Issuer()
    {
        var failures = Validate(new AuthorizationServerOptions { Issuer = "not-a-uri-at-all" });

        failures.Should().ContainSingle(f => f.Code == "configuration.issuer.invalid");
    }

    // ── Query component ───────────────────────────────────────────────────────────────────────────

    [Fact]
    public void Validate_fails_when_Issuer_has_query_string()
    {
        var failures = Validate(new AuthorizationServerOptions
        {
            Issuer = "https://auth.example.com?tenant=1",
        });

        failures.Should().ContainSingle(f => f.Code == "configuration.issuer.query")
            .Which.Message.Should().Contain("query");
    }

    [Fact]
    public void Validate_fails_when_Issuer_has_path_and_query_string()
    {
        var failures = Validate(new AuthorizationServerOptions
        {
            Issuer = "https://auth.example.com/tenant1?param=value",
        });

        failures.Should().ContainSingle(f => f.Code == "configuration.issuer.query")
            .Which.Message.Should().Contain("query");
    }

    // ── Fragment component ────────────────────────────────────────────────────────────────────────

    [Fact]
    public void Validate_fails_when_Issuer_has_fragment()
    {
        var failures = Validate(new AuthorizationServerOptions
        {
            Issuer = "https://auth.example.com#section",
        });

        failures.Should().ContainSingle(f => f.Code == "configuration.issuer.fragment")
            .Which.Message.Should().Contain("fragment");
    }

    [Fact]
    public void Validate_fails_when_Issuer_has_user_info()
    {
        var failures = Validate(new AuthorizationServerOptions
        {
            Issuer = "https://user:pass@auth.example.com",
        });

        failures.Should().ContainSingle(f => f.Code == "configuration.issuer.userinfo")
            .Which.Message.Should().Contain("user information");
    }

    // ── HTTPS requirement ─────────────────────────────────────────────────────────────────────────

    [Fact]
    public void Validate_fails_for_HTTP_Issuer_without_AllowHttpLoopbackIssuer_flag()
    {
        var failures = Validate(new AuthorizationServerOptions
        {
            Issuer = "http://auth.example.com",
            Development = { AllowHttpLoopbackIssuer = false },
        });

        failures.Should().ContainSingle(f => f.Code == "configuration.issuer.not_https")
            .Which.Message.Should().Contain("scheme");
    }

    [Fact]
    public void Validate_succeeds_for_HTTP_Issuer_with_AllowHttpLoopbackIssuer_flag()
    {
        var failures = Validate(new AuthorizationServerOptions
        {
            Issuer = "http://localhost:5000",
            Development = { AllowHttpLoopbackIssuer = true },
        });

        failures.Should().BeEmpty();
    }

    [Fact]
    public void Validate_fails_for_HTTP_non_loopback_Issuer_with_AllowHttpLoopbackIssuer_flag()
    {
        var failures = Validate(new AuthorizationServerOptions
        {
            Issuer = "http://auth.example.com",
            Development = { AllowHttpLoopbackIssuer = true },
        });

        failures.Should().ContainSingle(f => f.Code == "configuration.issuer.http_non_loopback")
            .Which.Message.Should().Contain("loopback");
    }

    [Theory]
    [InlineData("https://auth.example.com/tenant1/")]
    [InlineData("https://auth.example.com/a/b/c/")]
    [InlineData("http://localhost:5000/tenant1/", true)]
    public void Validate_fails_when_Issuer_has_trailing_slash_on_path(string issuer, bool allowInsecure = false)
    {
        var failures = Validate(new AuthorizationServerOptions
        {
            Issuer = issuer,
            Development = { AllowHttpLoopbackIssuer = allowInsecure },
        });

        failures.Should().ContainSingle(f => f.Code == "configuration.issuer.trailing_slash")
            .Which.Message.Should().Contain("trailing slash");
    }

    [Fact]
    public void Validate_succeeds_for_HTTPS_root_Issuer_with_no_path()
    {
        // https://auth.example.com has AbsolutePath "/" — must not be treated as trailing slash
        var failures = Validate(new AuthorizationServerOptions { Issuer = "https://auth.example.com" });
        failures.Should().BeEmpty();
    }

    [Fact]
    public void Validate_fails_once_for_HTTPS_root_Issuer_with_trailing_slash()
    {
        // The document publishes the issuer verbatim, but RFC 8414 §3.1 strips the terminating
        // "/" when building the metadata URL — so a client configured with "https://auth.example.com"
        // would reject a document whose issuer is "https://auth.example.com/" (§3.3).
        var failures = Validate(new AuthorizationServerOptions { Issuer = "https://auth.example.com/" });

        failures.Should().ContainSingle(
            because: "the trailing-slash rule reports it; the canonical-form rule must not report the same slash again")
            .Which.Should().Match<ZeeKayDaConfigurationFailure>(
                f => f.Code == "configuration.issuer.trailing_slash" && f.Message.Contains("trailing slash"));
    }

    [Fact]
    public void Validate_succeeds_for_Issuer_with_non_default_HTTPS_port()
    {
        // Port 8443 ≠ 443, so isDefaultPort = false and the port is preserved in the canonical
        // form, making the input identical to the canonical — no "not canonical" failure.
        var failures = Validate(new AuthorizationServerOptions { Issuer = "https://auth.example.com:8443" });
        failures.Should().BeEmpty();
    }

    [Fact]
    public void Validate_fails_with_canonical_suggestion_when_Issuer_host_is_uppercase()
    {
        var failures = Validate(new AuthorizationServerOptions
        {
            Issuer = "https://AUTH.example.com",
        });

        failures.Should().ContainSingle(f => f.Code == "configuration.issuer.not_canonical")
            .Which.Message.Should().Contain("is not canonical").And.Contain("https://auth.example.com");
    }

    [Fact]
    public void Validate_fails_with_canonical_suggestion_when_Issuer_scheme_is_uppercase()
    {
        var failures = Validate(new AuthorizationServerOptions
        {
            Issuer = "HTTPS://auth.example.com",
        });

        failures.Should().ContainSingle(f => f.Code == "configuration.issuer.not_canonical")
            .Which.Message.Should().Contain("is not canonical").And.Contain("https://auth.example.com");
    }

    [Fact]
    public void Validate_fails_with_canonical_suggestion_when_Issuer_has_explicit_default_HTTPS_port()
    {
        var failures = Validate(new AuthorizationServerOptions
        {
            Issuer = "https://auth.example.com:443",
        });

        failures.Should().ContainSingle(f => f.Code == "configuration.issuer.not_canonical")
            .Which.Message.Should().Contain("is not canonical").And.Contain("https://auth.example.com");
    }

    [Fact]
    public void Validate_fails_with_canonical_suggestion_when_Issuer_has_explicit_default_HTTP_port_for_loopback()
    {
        var failures = Validate(new AuthorizationServerOptions
        {
            Issuer = "http://localhost:80",
            Development = { AllowHttpLoopbackIssuer = true },
        });

        failures.Should().ContainSingle(f => f.Code == "configuration.issuer.not_canonical")
            .Which.Message.Should().Contain("is not canonical").And.Contain("http://localhost");
    }

    [Theory]
    [InlineData("ftp://localhost")]
    [InlineData("file:///tmp/auth")]
    [InlineData("custom://localhost")]
    public void Validate_fails_for_non_HTTP_or_HTTPS_scheme_Issuer_even_with_AllowHttpLoopbackIssuer_flag(string issuer)
    {
        var failures = Validate(new AuthorizationServerOptions
        {
            Issuer = issuer,
            Development = { AllowHttpLoopbackIssuer = true },
        });

        failures.Should().ContainSingle(f => f.Code == "configuration.issuer.not_https")
            .Which.Message.Should().Contain("scheme");
    }

    [Fact]
    public void Validate_fails_when_ResponseTypesSupported_is_null()
    {
        var failures = Validate(new AuthorizationServerOptions
        {
            Issuer = "https://auth.example.com",
            Response = { TypesSupported = null! },
        });

        failures.Should().ContainSingle(f => f.Code == "configuration.response.types_supported.null")
            .Which.Message.Should().Contain("Response.TypesSupported");
    }

    [Fact]
    public void Validate_fails_when_ResponseTypesSupported_is_empty()
    {
        var failures = Validate(new AuthorizationServerOptions
        {
            Issuer = "https://auth.example.com",
            Response = { TypesSupported = [] },
        });

        failures.Should().ContainSingle(f => f.Code == "configuration.response.types_supported.empty")
            .Which.Message.Should().Contain("Response.TypesSupported");
    }

    [Fact]
    public void Validate_fails_when_ResponseModesSupported_is_null()
    {
        var failures = Validate(new AuthorizationServerOptions
        {
            Issuer = "https://auth.example.com",
            Response = { ModesSupported = null! },
        });

        failures.Should().ContainSingle(f => f.Code == "configuration.response.modes_supported.null")
            .Which.Message.Should().Contain("Response.ModesSupported");
    }

    [Fact]
    public void Validate_fails_when_CorsOrigins_is_null()
    {
        var failures = Validate(new AuthorizationServerOptions
        {
            Issuer = "https://auth.example.com",
            CorsOrigins = null!,
        });

        failures.Should().ContainSingle(f => f.Code == "configuration.cors_origins.null")
            .Which.Message.Should().Contain(nameof(AuthorizationServerOptions.CorsOrigins));
    }

    [Fact]
    public void Validate_fails_when_GrantTypesSupported_is_null()
    {
        var failures = Validate(new AuthorizationServerOptions
        {
            Issuer = "https://auth.example.com",
            GrantTypesSupported = null!,
        });

        failures.Should().ContainSingle(f => f.Code == "configuration.grant_types_supported.null")
            .Which.Message.Should().Contain(nameof(AuthorizationServerOptions.GrantTypesSupported));
    }

    [Fact]
    public void Validate_fails_when_GrantTypesSupported_contains_out_of_range_value()
    {
        var failures = Validate(new AuthorizationServerOptions
        {
            Issuer = "https://auth.example.com",
            GrantTypesSupported = [(GrantType)9999],
        });

        failures.Should().ContainSingle(f => f.Code == "configuration.grant_types_supported.undefined_value")
            .Which.Message.Should().Contain("GrantTypesSupported").And.Contain(nameof(GrantType));
    }

    [Fact]
    public void Validate_succeeds_when_AdvertisedAuthMethods_is_null()
    {
        var failures = Validate(new AuthorizationServerOptions
        {
            Issuer = "https://auth.example.com",
            TokenEndpoint = { AdvertisedAuthMethods = null },
        });

        failures.Should().BeEmpty();
    }

    [Fact]
    public void Validate_fails_when_AdvertisedAuthMethods_is_empty()
    {
        var failures = Validate(new AuthorizationServerOptions
        {
            Issuer = "https://auth.example.com",
            TokenEndpoint = { AdvertisedAuthMethods = [] },
        });

        failures.Should().ContainSingle(f => f.Code == "configuration.token_endpoint.advertised_auth_methods.empty")
            .Which.Message.Should().Contain("TokenEndpoint.AdvertisedAuthMethods");
    }

    [Theory]
    [InlineData(null, "configuration.issuer.missing")]
    [InlineData("not-a-uri", "configuration.issuer.invalid")]
    public void An_issuer_that_does_not_parse_is_the_only_failure_reported(string? issuer, string expectedCode)
    {
        // Every other rule here is broken too; none can be judged without a parsed issuer.
        var failures = Validate(new AuthorizationServerOptions
        {
            Issuer = issuer,
            ClockSkewTolerance = TimeSpan.FromSeconds(-1),
            AuthorizationEndpoint = { AuthorizationCodeLifetime = TimeSpan.Zero },
            TokenEndpoint = { AdvertisedAuthMethods = [] },
        });

        failures.Should().ContainSingle().Which.Code.Should().Be(expectedCode);
    }

    [Fact]
    public void Validate_fails_when_AdvertisedAuthMethods_contains_empty_string()
    {
        var failures = Validate(new AuthorizationServerOptions
        {
            Issuer = "https://auth.example.com",
            TokenEndpoint = { AdvertisedAuthMethods = [""] },
        });

        failures.Should().ContainSingle(f => f.Code == "configuration.token_endpoint.advertised_auth_methods.invalid_entry")
            .Which.Message.Should().Contain("TokenEndpoint.AdvertisedAuthMethods");
    }

    [Fact]
    public void Validate_fails_when_AdvertisedAuthMethods_contains_whitespace_only_string()
    {
        var failures = Validate(new AuthorizationServerOptions
        {
            Issuer = "https://auth.example.com",
            TokenEndpoint = { AdvertisedAuthMethods = ["   "] },
        });

        failures.Should().ContainSingle(f => f.Code == "configuration.token_endpoint.advertised_auth_methods.invalid_entry")
            .Which.Message.Should().Contain("TokenEndpoint.AdvertisedAuthMethods");
    }

    [Fact]
    public void Validate_fails_when_AdvertisedAuthMethods_contains_leading_whitespace()
    {
        var failures = Validate(new AuthorizationServerOptions
        {
            Issuer = "https://auth.example.com",
            TokenEndpoint = { AdvertisedAuthMethods = [" client_secret_basic"] },
        });

        failures.Should().ContainSingle(f => f.Code == "configuration.token_endpoint.advertised_auth_methods.invalid_entry")
            .Which.Message.Should().Contain("TokenEndpoint.AdvertisedAuthMethods");
    }

    [Fact]
    public void Validate_fails_when_AdvertisedAuthMethods_contains_control_character()
    {
        var failures = Validate(new AuthorizationServerOptions
        {
            Issuer = "https://auth.example.com",
            TokenEndpoint = { AdvertisedAuthMethods = ["client\x00secret"] },
        });

        failures.Should().ContainSingle(f => f.Code == "configuration.token_endpoint.advertised_auth_methods.invalid_entry")
            .Which.Message.Should().Contain("TokenEndpoint.AdvertisedAuthMethods");
    }

    [Fact]
    public void Validate_succeeds_when_AdvertisedAuthMethods_contains_custom_method_string()
    {
        var failures = Validate(new AuthorizationServerOptions
        {
            Issuer = "https://auth.example.com",
            TokenEndpoint = { AdvertisedAuthMethods = ["tls_client_auth"] },
        });

        failures.Should().BeEmpty();
    }

    [Fact]
    public void Validate_succeeds_when_AdvertisedSigningAlgorithms_is_null()
    {
        var failures = Validate(new AuthorizationServerOptions
        {
            Issuer = "https://auth.example.com",
            IdToken = { AdvertisedSigningAlgorithms = null },
        });

        failures.Should().BeEmpty("null is the default and advertises every algorithm in the published key set");
    }

    [Fact]
    public void Validate_fails_when_AdvertisedSigningAlgorithms_is_empty()
    {
        var failures = Validate(new AuthorizationServerOptions
        {
            Issuer = "https://auth.example.com",
            IdToken = { AdvertisedSigningAlgorithms = [] },
        });

        failures.Should().ContainSingle(f => f.Code == "configuration.id_token.advertised_signing_algorithms.empty")
            .Which.Message.Should().Contain("IdToken.AdvertisedSigningAlgorithms").And.Contain("set it to null");
    }

    [Fact]
    public void Validate_succeeds_when_AdvertisedSigningAlgorithms_names_an_algorithm()
    {
        var failures = Validate(new AuthorizationServerOptions
        {
            Issuer = "https://auth.example.com",
            IdToken = { AdvertisedSigningAlgorithms = [SigningAlgorithm.RS256] },
        });

        failures.Should().BeEmpty("reconciling the filter with the key set needs a key set, so it happens at startup");
    }

    // ── AuthorizationEndpoint.CodeChallengeMethodsSupported ───────────────────────────────────────

    [Fact]
    public void CodeChallengeMethodsSupported_defaults_to_S256()
    {
        new AuthorizationServerOptions().AuthorizationEndpoint.CodeChallengeMethodsSupported
            .Should().Equal([CodeChallengeMethod.S256], "the token endpoint enforces S256, so advertising it is truthful from the first start");
    }

    [Fact]
    public void Validate_succeeds_when_CodeChallengeMethodsSupported_is_null_on_a_host_without_the_code_grant()
    {
        var failures = Validate(new AuthorizationServerOptions
        {
            Issuer = "https://auth.example.com",
            GrantTypesSupported = [GrantType.ClientCredentials],
            AuthorizationEndpoint = { CodeChallengeMethodsSupported = null },
        });

        failures.Should().BeEmpty("nothing on such a host relies on PKCE");
    }

    [Fact]
    public void Validate_fails_when_the_code_grant_is_served_without_S256()
    {
        // The audit's gate: the grant may not be advertised with the enforcement path missing.
        var failures = Validate(new AuthorizationServerOptions
        {
            Issuer = "https://auth.example.com",
            GrantTypesSupported = [GrantType.AuthorizationCode],
            AuthorizationEndpoint = { CodeChallengeMethodsSupported = null },
        });

        failures.Should().ContainSingle(f => f.Code == "configuration.authorization_endpoint.code_challenge_methods_supported.s256_missing")
            .Which.Message.Should().Contain("CodeChallengeMethodsSupported must contain CodeChallengeMethod.S256");
    }

    [Fact]
    public void Validate_succeeds_when_CodeChallengeMethodsSupported_contains_S256()
    {
        var failures = Validate(new AuthorizationServerOptions
        {
            Issuer = "https://auth.example.com",
            AuthorizationEndpoint = { CodeChallengeMethodsSupported = [CodeChallengeMethod.S256] },
        });

        failures.Should().BeEmpty();
    }

    // ── TokenEndpoint.AccessTokenLifetime / IdTokenLifetime ──────────────────────────────────────

    // An access token is a self-contained JWT checked against no store, so the default lifetime is
    // the window in which it still works after the grant behind it is gone (RFC 7009 section 3).
    [Fact]
    public void Token_lifetimes_default_to_ten_minutes_and_five_minutes()
    {
        var options = new AuthorizationServerOptions().TokenEndpoint;

        options.AccessTokenLifetime.Should().Be(TimeSpan.FromMinutes(10));
        options.IdTokenLifetime.Should().Be(TimeSpan.FromMinutes(5));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    public void Validate_fails_when_AccessTokenLifetime_is_not_positive(int seconds)
    {
        var failures = Validate(new AuthorizationServerOptions
        {
            Issuer = "https://auth.example.com",
            TokenEndpoint = { AccessTokenLifetime = TimeSpan.FromSeconds(seconds) },
        });

        failures.Should().ContainSingle(f => f.Code == "configuration.token_endpoint.access_token_lifetime.not_positive")
            .Which.Message.Should().Contain("TokenEndpoint.AccessTokenLifetime must be greater than zero");
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    public void Validate_fails_when_IdTokenLifetime_is_not_positive(int seconds)
    {
        var failures = Validate(new AuthorizationServerOptions
        {
            Issuer = "https://auth.example.com",
            TokenEndpoint = { IdTokenLifetime = TimeSpan.FromSeconds(seconds) },
        });

        failures.Should().ContainSingle(f => f.Code == "configuration.token_endpoint.id_token_lifetime.not_positive")
            .Which.Message.Should().Contain("TokenEndpoint.IdTokenLifetime must be greater than zero");
    }

    [Fact]
    public void Validate_places_no_upper_bound_on_token_lifetimes()
    {
        var failures = Validate(new AuthorizationServerOptions
        {
            Issuer = "https://auth.example.com",
            TokenEndpoint = { AccessTokenLifetime = TimeSpan.FromDays(365), IdTokenLifetime = TimeSpan.FromDays(365) },
        });

        failures.Should().BeEmpty("a lifetime past the family ceiling warns at startup rather than failing it");
    }

    [Fact]
    public void Validate_fails_when_CodeChallengeMethodsSupported_is_empty()
    {
        var failures = Validate(new AuthorizationServerOptions
        {
            Issuer = "https://auth.example.com",
            AuthorizationEndpoint = { CodeChallengeMethodsSupported = [] },
        });

        failures.Should().ContainSingle(f => f.Code == "configuration.authorization_endpoint.code_challenge_methods_supported.empty")
            .Which.Message.Should().Contain("AuthorizationEndpoint.CodeChallengeMethodsSupported");
    }

    // ── Happy paths ───────────────────────────────────────────────────────────────────────────────

    [Fact]
    public void Validate_succeeds_for_valid_HTTPS_Issuer()
    {
        var failures = Validate(new AuthorizationServerOptions
        {
            Issuer = "https://auth.example.com",
        });

        failures.Should().BeEmpty();
    }

    [Fact]
    public void Validate_succeeds_for_valid_HTTPS_Issuer_with_path()
    {
        var failures = Validate(new AuthorizationServerOptions
        {
            Issuer = "https://auth.example.com/tenant1",
        });

        failures.Should().BeEmpty();
    }

    // ── Endpoint URI overrides ────────────────────────────────────────────────────────────────────

    [Theory]
    [InlineData("AuthorizationEndpoint.Uri", "not-a-uri", "configuration.authorization_endpoint.uri.invalid")]
    [InlineData("TokenEndpoint.Uri", "not-a-uri", "configuration.token_endpoint.uri.invalid")]
    [InlineData("JwksEndpoint.Uri", "not-a-uri", "configuration.jwks_endpoint.uri.invalid")]
    [InlineData("EndSessionEndpoint.Uri", "not-a-uri", "configuration.end_session_endpoint.uri.invalid")]
    public void Validate_fails_when_endpoint_override_is_not_an_absolute_URI(string propertyPath, string value, string expectedCode)
    {
        var options = new AuthorizationServerOptions { Issuer = "https://auth.example.com" };
        SetGroupProperty(options, propertyPath, value);

        var failures = Validate(options);

        failures.Should().ContainSingle(f => f.Code == expectedCode)
            .Which.Message.Should().Contain("Uri");
    }

    [Theory]
    [InlineData("AuthorizationEndpoint.Uri", "not-a-uri", "configuration.authorization_endpoint.uri.invalid")]
    [InlineData("TokenEndpoint.Uri", "not-a-uri", "configuration.token_endpoint.uri.invalid")]
    [InlineData("JwksEndpoint.Uri", "not-a-uri", "configuration.jwks_endpoint.uri.invalid")]
    [InlineData("AuthorizationEndpoint.Uri", "https://evil.example.com/connect/authorize", "configuration.authorization_endpoint.uri.authority_mismatch")]
    [InlineData("TokenEndpoint.Uri", "https://evil.example.com/connect/token", "configuration.token_endpoint.uri.authority_mismatch")]
    [InlineData("JwksEndpoint.Uri", "https://evil.example.com/connect/jwks", "configuration.jwks_endpoint.uri.authority_mismatch")]
    [InlineData("EndSessionEndpoint.Uri", "not-a-uri", "configuration.end_session_endpoint.uri.invalid")]
    [InlineData("EndSessionEndpoint.Uri", "https://evil.example.com/connect/endsession", "configuration.end_session_endpoint.uri.authority_mismatch")]
    public void Validate_failure_message_names_the_endpoint_override_it_is_about(string propertyPath, string value, string expectedCode)
    {
        var options = new AuthorizationServerOptions { Issuer = "https://auth.example.com" };
        SetGroupProperty(options, propertyPath, value);

        var failures = Validate(options);

        failures.Should().ContainSingle(f => f.Code == expectedCode)
            .Which.Message.Should().Contain($"AuthorizationServerOptions.{propertyPath}");
    }

    [Fact]
    public void Validate_failure_messages_never_repeat_the_issuers_user_information_query_or_fragment()
    {
        var failures = Validate(new AuthorizationServerOptions
        {
            Issuer = "https://admin:s3cret@Auth.Example.com/?token=t0ken#fr4g",
        });

        failures.Should().NotBeEmpty();
        failures.Should().AllSatisfy(f => f.Message.Should()
            .NotContain("s3cret").And.NotContain("t0ken").And.NotContain("fr4g"));
    }

    [Fact]
    public void Validate_failure_messages_never_repeat_an_endpoint_overrides_user_information_or_query()
    {
        var failures = Validate(new AuthorizationServerOptions
        {
            Issuer = "https://auth.example.com",
            JwksEndpoint = { Uri = "http://admin:s3cret@evil.example.com/jwks?sig=t0ken" },
        });

        failures.Should().Contain(f => f.Code.StartsWith("configuration.jwks_endpoint.uri.", StringComparison.Ordinal));
        failures.Should().AllSatisfy(f => f.Message.Should().NotContain("s3cret").And.NotContain("t0ken"));
    }

    [Fact]
    public void Validate_query_failure_message_never_repeats_an_endpoint_overrides_query()
    {
        var failures = Validate(new AuthorizationServerOptions
        {
            Issuer = "https://auth.example.com",
            JwksEndpoint = { Uri = "https://auth.example.com/jwks?sig=t0ken" },
        });

        failures.Should().ContainSingle(f => f.Code == "configuration.jwks_endpoint.uri.query")
            .Which.Message.Should().NotContain("t0ken");
    }

    [Fact]
    public void Validate_authority_mismatch_message_never_repeats_the_issuers_user_information()
    {
        var failures = Validate(new AuthorizationServerOptions
        {
            Issuer = "https://admin:s3cret@auth.example.com",
            TokenEndpoint = { Uri = "https://other.example.com/connect/token" },
        });

        failures.Should().ContainSingle(f => f.Code == "configuration.token_endpoint.uri.authority_mismatch")
            .Which.Message.Should().NotContain("s3cret");
    }

    [Theory]
    [InlineData("https://admin:s3cret@app.example.com")]
    [InlineData("https://app.example.com/?sig=s3cret")]
    [InlineData("https://app.example.com/#s3cret")]
    [InlineData("https://app.example.com\r\nX-Injected: s3cret")]
    public void Validate_CORS_failure_messages_never_repeat_an_origins_secrets_or_line_breaks(string origin)
    {
        var failures = Validate(new AuthorizationServerOptions
        {
            Issuer = "https://auth.example.com",
            CorsOrigins = [origin],
        });

        failures.Should().ContainSingle(f => f.Code == "configuration.cors_origins.invalid")
            .Which.Message.Should().StartWith("AuthorizationServerOptions.CorsOrigins[0]: ")
            .And.NotContain("s3cret").And.NotContain("\r").And.NotContain("\n");
    }

    [Theory]
    [InlineData("AuthorizationEndpoint.Uri", "http://auth.example.com/connect/authorize", "configuration.authorization_endpoint.uri.not_https")]
    [InlineData("TokenEndpoint.Uri", "http://auth.example.com/connect/token", "configuration.token_endpoint.uri.not_https")]
    [InlineData("JwksEndpoint.Uri", "http://auth.example.com/connect/jwks", "configuration.jwks_endpoint.uri.not_https")]
    [InlineData("EndSessionEndpoint.Uri", "http://auth.example.com/connect/endsession", "configuration.end_session_endpoint.uri.not_https")]
    public void Validate_fails_for_HTTP_endpoint_override_without_AllowHttpLoopbackIssuer_flag(string propertyPath, string value, string expectedCode)
    {
        var options = new AuthorizationServerOptions { Issuer = "https://auth.example.com" };
        SetGroupProperty(options, propertyPath, value);

        var failures = Validate(options);

        failures.Should().ContainSingle(f => f.Code == expectedCode)
            .Which.Message.Should().Contain("HTTPS");
    }

    [Theory]
    [InlineData("AuthorizationEndpoint.Uri", "https://auth.example.com/connect/authorize")]
    [InlineData("TokenEndpoint.Uri", "https://auth.example.com/connect/token")]
    [InlineData("JwksEndpoint.Uri", "https://auth.example.com/connect/jwks")]
    [InlineData("EndSessionEndpoint.Uri", "https://auth.example.com/connect/endsession")]
    public void Validate_succeeds_for_HTTPS_endpoint_override(string propertyPath, string value)
    {
        var options = new AuthorizationServerOptions { Issuer = "https://auth.example.com" };
        SetGroupProperty(options, propertyPath, value);

        var failures = Validate(options);

        failures.Should().BeEmpty();
    }

    [Theory]
    [InlineData("AuthorizationEndpoint.Uri", "https://evil.example.com/connect/authorize", "configuration.authorization_endpoint.uri.authority_mismatch")]
    [InlineData("TokenEndpoint.Uri", "https://evil.example.com/connect/token", "configuration.token_endpoint.uri.authority_mismatch")]
    [InlineData("JwksEndpoint.Uri", "https://evil.example.com/connect/jwks", "configuration.jwks_endpoint.uri.authority_mismatch")]
    [InlineData("EndSessionEndpoint.Uri", "https://evil.example.com/connect/endsession", "configuration.end_session_endpoint.uri.authority_mismatch")]
    public void Validate_fails_when_endpoint_override_has_different_authority(string propertyPath, string value, string expectedCode)
    {
        var options = new AuthorizationServerOptions { Issuer = "https://auth.example.com" };
        SetGroupProperty(options, propertyPath, value);

        var failures = Validate(options);

        failures.Should().ContainSingle(f => f.Code == expectedCode)
            .Which.Message.Should().Contain("same authority");
    }

    [Theory]
    [InlineData("AuthorizationEndpoint.Uri", "https://auth.example.com:443/connect/authorize")]
    [InlineData("TokenEndpoint.Uri", "https://auth.example.com:443/connect/token")]
    [InlineData("JwksEndpoint.Uri", "https://auth.example.com:443/connect/jwks")]
    public void Validate_succeeds_when_endpoint_override_has_same_host_with_default_port(string propertyPath, string value)
    {
        var options = new AuthorizationServerOptions { Issuer = "https://auth.example.com" };
        SetGroupProperty(options, propertyPath, value);

        var failures = Validate(options);

        failures.Should().BeEmpty();
    }

    [Theory]
    [InlineData("AuthorizationEndpoint.Uri", "https://AUTH.example.com/connect/authorize")]
    [InlineData("TokenEndpoint.Uri", "https://AUTH.example.com/connect/token")]
    [InlineData("JwksEndpoint.Uri", "https://AUTH.example.com/connect/jwks")]
    public void Validate_succeeds_when_endpoint_override_has_same_authority_with_case_insensitive_host(string propertyPath, string value)
    {
        var options = new AuthorizationServerOptions { Issuer = "https://auth.example.com" };
        SetGroupProperty(options, propertyPath, value);

        var failures = Validate(options);

        failures.Should().BeEmpty();
    }

    [Theory]
    [InlineData("AuthorizationEndpoint.Uri", "https://auth.example.com:8443/connect/authorize", "configuration.authorization_endpoint.uri.authority_mismatch")]
    [InlineData("TokenEndpoint.Uri", "https://auth.example.com:8443/connect/token", "configuration.token_endpoint.uri.authority_mismatch")]
    [InlineData("JwksEndpoint.Uri", "https://auth.example.com:8443/connect/jwks", "configuration.jwks_endpoint.uri.authority_mismatch")]
    public void Validate_fails_when_endpoint_override_has_different_port(string propertyPath, string value, string expectedCode)
    {
        var options = new AuthorizationServerOptions { Issuer = "https://auth.example.com" };
        SetGroupProperty(options, propertyPath, value);

        var failures = Validate(options);

        failures.Should().ContainSingle(f => f.Code == expectedCode)
            .Which.Message.Should().Contain("same authority");
    }

    [Theory]
    [InlineData("AuthorizationEndpoint.Uri", "https://user:pass@auth.example.com/connect/authorize", "configuration.authorization_endpoint.uri.userinfo")]
    [InlineData("TokenEndpoint.Uri", "https://user:pass@auth.example.com/connect/token", "configuration.token_endpoint.uri.userinfo")]
    [InlineData("JwksEndpoint.Uri", "https://user:pass@auth.example.com/connect/jwks", "configuration.jwks_endpoint.uri.userinfo")]
    public void Validate_fails_when_endpoint_override_has_user_info(string propertyPath, string value, string expectedCode)
    {
        var options = new AuthorizationServerOptions { Issuer = "https://auth.example.com" };
        SetGroupProperty(options, propertyPath, value);

        var failures = Validate(options);

        failures.Should().ContainSingle(f => f.Code == expectedCode)
            .Which.Message.Should().Contain("user information");
    }

    [Theory]
    [InlineData("AuthorizationEndpoint.Uri", "http://auth.example.com/connect/authorize", "configuration.authorization_endpoint.uri.http_non_loopback")]
    [InlineData("TokenEndpoint.Uri", "http://auth.example.com/connect/token", "configuration.token_endpoint.uri.http_non_loopback")]
    [InlineData("JwksEndpoint.Uri", "http://auth.example.com/connect/jwks", "configuration.jwks_endpoint.uri.http_non_loopback")]
    public void Validate_fails_for_HTTP_non_loopback_endpoint_override_with_AllowHttpLoopbackIssuer_flag(string propertyPath, string value, string expectedCode)
    {
        var options = new AuthorizationServerOptions
        {
            Issuer = "https://auth.example.com",
            Development = { AllowHttpLoopbackIssuer = true },
        };
        SetGroupProperty(options, propertyPath, value);

        var failures = Validate(options);

        failures.Should().ContainSingle(f => f.Code == expectedCode)
            .Which.Message.Should().Contain("loopback");
    }

    [Theory]
    [InlineData("AuthorizationEndpoint.Uri", "https://auth.example.com/connect/authorize#fragment", "configuration.authorization_endpoint.uri.fragment")]
    [InlineData("TokenEndpoint.Uri", "https://auth.example.com/connect/token#fragment", "configuration.token_endpoint.uri.fragment")]
    public void Validate_fails_when_endpoint_override_has_fragment(string propertyPath, string value, string expectedCode)
    {
        var options = new AuthorizationServerOptions { Issuer = "https://auth.example.com" };
        SetGroupProperty(options, propertyPath, value);

        var failures = Validate(options);

        failures.Should().ContainSingle(f => f.Code == expectedCode);
    }

    [Theory]
    // RFC 6749 §3.1 and §3.2 carry the same sentence for the authorization and token endpoints
    // alike: the endpoint URI MAY include a query component. Neither is merely unprohibited.
    [InlineData("AuthorizationEndpoint.Uri", "https://auth.example.com/connect/authorize?foo=bar")]
    [InlineData("TokenEndpoint.Uri", "https://auth.example.com/connect/token?foo=bar")]
    public void Validate_succeeds_when_endpoint_override_has_query(string propertyPath, string value)
    {
        var options = new AuthorizationServerOptions { Issuer = "https://auth.example.com" };
        SetGroupProperty(options, propertyPath, value);

        var failures = Validate(options);

        failures.Should().BeEmpty();
    }

    [Theory]
    [InlineData("https://auth.example.com/connect/jwks?foo=bar", "configuration.jwks_endpoint.uri.query")]
    [InlineData("https://auth.example.com/connect/jwks#fragment", "configuration.jwks_endpoint.uri.fragment")]
    public void Validate_fails_when_JWKS_URI_override_has_query_or_fragment(string value, string expectedCode)
    {
        var failures = Validate(new AuthorizationServerOptions
        {
            Issuer = "https://auth.example.com",
            JwksEndpoint = { Uri = value },
        });

        failures.Should().ContainSingle(f => f.Code == expectedCode);
    }

    // ── Cache-Control max-age ─────────────────────────────────────────────────────────────────────

    [Fact]
    public void Validate_fails_for_negative_discovery_cache_max_age()
    {
        var failures = Validate(new AuthorizationServerOptions
        {
            Issuer = "https://auth.example.com",
            DiscoveryDocument = { CacheMaxAge = TimeSpan.FromSeconds(-1) },
        });

        failures.Should().ContainSingle(f => f.Code == "configuration.discovery_document.cache_max_age.negative")
            .Which.Message.Should().Contain("DiscoveryDocument.CacheMaxAge");
    }

    [Fact]
    public void Validate_fails_for_negative_jwks_cache_max_age()
    {
        var failures = Validate(new AuthorizationServerOptions
        {
            Issuer = "https://auth.example.com",
            JwksEndpoint = { CacheMaxAge = TimeSpan.FromSeconds(-1) },
        });

        failures.Should().ContainSingle(f => f.Code == "configuration.jwks_endpoint.cache_max_age.negative")
            .Which.Message.Should().Contain("JwksEndpoint.CacheMaxAge");
    }

    // ── CorsOrigins — one allowlist for every endpoint that answers a script ─────────────────────

    [Fact]
    public void Validate_fails_for_a_wildcard_origin_and_names_the_option()
    {
        var options = new AuthorizationServerOptions { Issuer = "https://auth.example.com" };
        options.CorsOrigins.Add("https://*.example.com");

        var failures = Validate(options);

        failures.Should().ContainSingle(f => f.Code == "configuration.cors_origins.invalid")
            .Which.Message.Should().Contain("wildcard").And.Contain(
                "AuthorizationServerOptions.CorsOrigins",
                because: "the failure must name the option the operator has to fix");
    }

    [Fact]
    public void Validate_fails_with_named_list_for_an_origin_whose_host_is_not_a_valid_idn()
    {
        var options = new AuthorizationServerOptions { Issuer = "https://auth.example.com" };
        options.CorsOrigins.Add("https://℀.example");

        var failures = Validate(options);

        failures.Should().ContainSingle(f => f.Code == "configuration.cors_origins.invalid")
            .Which.Message.Should().Contain("AuthorizationServerOptions.CorsOrigins").And.Contain("valid host name");
    }

    [Fact]
    public void Validate_accepts_an_ipv6_loopback_origin_when_http_loopback_cors_origins_are_allowed()
    {
        var options = new AuthorizationServerOptions
        {
            Issuer = "https://auth.example.com",
            Development = { AllowHttpLoopbackCorsOrigins = true },
        };
        options.CorsOrigins.Add("http://[::1]:5001");

        var failures = Validate(options);

        failures.Should().BeEmpty();
    }

    // ── CorsOrigins — scheme validation ──────────────────────────────────────────────────────────

    [Fact]
    public void Validate_succeeds_for_HTTPS_CORS_origin()
    {
        var options = new AuthorizationServerOptions { Issuer = "https://auth.example.com" };
        options.CorsOrigins.Add("https://app.example.com");

        var failures = Validate(options);

        failures.Should().BeEmpty();
    }

    [Fact]
    public void Validate_fails_for_HTTP_CORS_origin_without_AllowHttpLoopbackCorsOrigins_flag()
    {
        var options = new AuthorizationServerOptions { Issuer = "https://auth.example.com" };
        options.CorsOrigins.Add("http://app.example.com");

        var failures = Validate(options);

        failures.Should().ContainSingle(f => f.Code == "configuration.cors_origins.invalid")
            .Which.Message.Should().Contain("http://app.example.com");
    }

    [Fact]
    public void Validate_fails_for_FTP_CORS_origin()
    {
        var options = new AuthorizationServerOptions { Issuer = "https://auth.example.com" };
        options.CorsOrigins.Add("ftp://files.example.com");

        var failures = Validate(options);

        failures.Should().ContainSingle(f => f.Code == "configuration.cors_origins.invalid")
            .Which.Message.Should().Contain("ftp://files.example.com");
    }

    [Fact]
    public void Validate_succeeds_for_HTTP_loopback_CORS_origin_with_AllowHttpLoopbackCorsOrigins_flag()
    {
        var options = new AuthorizationServerOptions
        {
            Issuer = "https://auth.example.com",
            Development = { AllowHttpLoopbackCorsOrigins = true },
        };
        options.CorsOrigins.Add("http://localhost:3000");

        var failures = Validate(options);

        failures.Should().BeEmpty();
    }

    [Fact]
    public void Validate_fails_for_HTTP_non_loopback_CORS_origin_with_AllowHttpLoopbackCorsOrigins_flag()
    {
        var options = new AuthorizationServerOptions
        {
            Issuer = "https://auth.example.com",
            Development = { AllowHttpLoopbackCorsOrigins = true },
        };
        options.CorsOrigins.Add("http://app.example.com");

        var failures = Validate(options);

        failures.Should().ContainSingle(f => f.Code == "configuration.cors_origins.invalid")
            .Which.Message.Should().Contain("loopback");
    }

    [Fact]
    public void Validate_fails_for_HTTP_loopback_CORS_origin_with_only_the_AllowHttpLoopbackIssuer_flag()
    {
        var options = new AuthorizationServerOptions
        {
            Issuer = "http://localhost",
            Development = { AllowHttpLoopbackIssuer = true },
        };
        options.CorsOrigins.Add("http://localhost:3000");

        var failures = Validate(options);

        failures.Should().ContainSingle(f => f.Code == "configuration.cors_origins.invalid")
            .Which.Message.Should().Contain("AllowHttpLoopbackCorsOrigins");
    }

    [Fact]
    public void Validate_fails_for_HTTP_loopback_Issuer_with_only_the_AllowHttpLoopbackCorsOrigins_flag()
    {
        var failures = Validate(new AuthorizationServerOptions
        {
            Issuer = "http://localhost",
            Development = { AllowHttpLoopbackCorsOrigins = true },
        });

        failures.Should().ContainSingle(f => f.Code == "configuration.issuer.not_https");
    }

    [Theory]
    [InlineData(null, "A null value is not a valid CORS origin.")]
    [InlineData("", "An empty string is not a valid CORS origin.")]
    [InlineData("https://app.example.com\r\nx:y", "must not contain CR or LF characters")]
    [InlineData("null", "'null' is not a valid CORS origin.")]
    [InlineData("https://*.example.com", "must not contain wildcard characters")]
    [InlineData("not-a-uri", "must be a valid absolute URI")]
    [InlineData("https://user@app.example.com", "must not contain user information")]
    [InlineData("https://app.example.com?x=1", "must not contain a query component")]
    [InlineData("https://app.example.com#frag", "must not contain a fragment component")]
    [InlineData("https://app.example.com/path", "must not contain a path component")]
    public void Validate_fails_with_specific_reason_for_invalid_CORS_origins(string? origin, string expectedMessageFragment)
    {
        var options = new AuthorizationServerOptions { Issuer = "https://auth.example.com" };
        options.CorsOrigins.Add(origin!);

        var failures = Validate(options);

        failures.Should().ContainSingle(f => f.Code == "configuration.cors_origins.invalid")
            .Which.Message.Should().Contain(expectedMessageFragment);
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

        var failures = Validate(options);

        failures.Should().ContainSingle(f => f.Code == "configuration.security_headers.referrer_policy.undefined_value")
            .Which.Message.Should().Contain("ReferrerPolicy");
    }

    [Fact]
    public void Validate_fails_when_CrossOriginResourcePolicy_is_out_of_range()
    {
        var options = new AuthorizationServerOptions
        {
            Issuer = "https://auth.example.com",
            SecurityHeaders = { CrossOriginResourcePolicy = (CrossOriginResourcePolicy)9999 },
        };

        var failures = Validate(options);

        failures.Should().ContainSingle(f => f.Code == "configuration.security_headers.cross_origin_resource_policy.undefined_value")
            .Which.Message.Should().Contain("CrossOriginResourcePolicy");
    }

    // ── Multi-error accumulation ──────────────────────────────────────────────────────────────────

    [Fact]
    public void Validate_accumulates_query_fragment_and_userinfo_errors_on_issuer_with_all_three_problems()
    {
        // https://user:pass@AUTH.example.com/path/?q=1#frag triggers:
        //   query, fragment, user-info, and canonicalization (uppercase host).
        var failures = Validate(new AuthorizationServerOptions
        {
            Issuer = "https://user:pass@AUTH.example.com/path/?q=1#frag",
        });

        failures.Select(f => f.Code).Should().Contain(
        [
            "configuration.issuer.query",
            "configuration.issuer.fragment",
            "configuration.issuer.userinfo",
            "configuration.issuer.not_canonical",
        ]);
    }

    [Fact]
    public void Validate_accumulates_multiple_AdvertisedAuthMethods_invalid_entries()
    {
        // Three distinct invalid entries: whitespace-only, padded, control character.
        // The validator must accumulate one error per entry rather than stopping at the first.
        var failures = Validate(new AuthorizationServerOptions
        {
            Issuer = "https://auth.example.com",
            TokenEndpoint = { AdvertisedAuthMethods = ["   ", " padded ", "ctrl\x00char"] },
        });

        failures.Where(f => f.Code == "configuration.token_endpoint.advertised_auth_methods.invalid_entry")
            .Should().HaveCount(3, "each of the three invalid entries must produce a separate error");
    }

    [Fact]
    public void Validate_accumulates_errors_across_different_groups()
    {
        // Bad issuer (trailing slash on path) combined with an empty advertised-algorithm filter.
        // Both errors must appear in a single result, proving cross-group accumulation.
        var failures = Validate(new AuthorizationServerOptions
        {
            Issuer = "https://auth.example.com/tenant1/",
            IdToken = { AdvertisedSigningAlgorithms = [] },
        });

        failures.Select(f => f.Code).Should().Contain(
        [
            "configuration.issuer.trailing_slash",
            "configuration.id_token.advertised_signing_algorithms.empty",
        ]);
    }

    // ── ValidateEndpointUri — user-info branch ────────────────────────────────────────────────────

    [Fact]
    public void Validate_ValidateEndpointUri_returns_error_when_AuthorizationEndpoint_has_user_info()
    {
        var failures = Validate(new AuthorizationServerOptions
        {
            Issuer = "https://auth.example.com",
            AuthorizationEndpoint = { Uri = "https://user:pass@auth.example.com/connect/authorize" },
        });

        failures.Should().ContainSingle(f => f.Code == "configuration.authorization_endpoint.uri.userinfo")
            .Which.Message.Should().Contain("user information");
    }

    // ── ValidateEndpointUri — HTTP scheme branch (no AllowHttpLoopbackIssuer) ────────────────────────

    [Fact]
    public void Validate_ValidateEndpointUri_returns_error_when_AuthorizationEndpoint_uses_HTTP_without_AllowHttpLoopbackIssuer()
    {
        var failures = Validate(new AuthorizationServerOptions
        {
            Issuer = "https://auth.example.com",
            Development = { AllowHttpLoopbackIssuer = false },
            AuthorizationEndpoint = { Uri = "http://auth.example.com/connect/authorize" },
        });

        failures.Should().ContainSingle(f => f.Code == "configuration.authorization_endpoint.uri.not_https")
            .Which.Message.Should().Contain("HTTPS");
    }

    // ── ValidateEndpointUri — HTTP non-loopback with AllowHttpLoopbackIssuer ─────────────────────────

    [Fact]
    public void Validate_ValidateEndpointUri_returns_error_when_AuthorizationEndpoint_uses_HTTP_non_loopback_with_AllowHttpLoopbackIssuer()
    {
        var failures = Validate(new AuthorizationServerOptions
        {
            Issuer = "https://auth.example.com",
            Development = { AllowHttpLoopbackIssuer = true },
            AuthorizationEndpoint = { Uri = "http://auth.example.com/connect/authorize" },
        });

        failures.Should().ContainSingle(f => f.Code == "configuration.authorization_endpoint.uri.http_non_loopback")
            .Which.Message.Should().Contain("loopback");
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
        // ClockSkewTolerance must be set below half of the (very short) 1-second code lifetime
        // to avoid triggering the cross-field clock-skew guard while testing the lifetime bound.
        var failures = Validate(new AuthorizationServerOptions
        {
            Issuer = "https://auth.example.com",
            AuthorizationEndpoint = { AuthorizationCodeLifetime = TimeSpan.FromSeconds(1) },
            ClockSkewTolerance = TimeSpan.Zero,
        });

        failures.Should().BeEmpty();
    }

    [Fact]
    public void Validate_succeeds_when_AuthorizationCodeLifetime_is_exactly_600_seconds()
    {
        var failures = Validate(new AuthorizationServerOptions
        {
            Issuer = "https://auth.example.com",
            AuthorizationEndpoint = { AuthorizationCodeLifetime = TimeSpan.FromSeconds(600) },
        });

        failures.Should().BeEmpty();
    }

    [Fact]
    public void Validate_fails_when_AuthorizationCodeLifetime_exceeds_600_seconds()
    {
        var failures = Validate(new AuthorizationServerOptions
        {
            Issuer = "https://auth.example.com",
            AuthorizationEndpoint = { AuthorizationCodeLifetime = TimeSpan.FromSeconds(601) },
        });

        failures.Should().ContainSingle(f => f.Code == "configuration.authorization_endpoint.authorization_code_lifetime.too_long")
            .Which.Message.Should().Contain("600 seconds").And.Contain("RFC 9700 §2.1.1");
    }

    [Fact]
    public void Validate_fails_when_AuthorizationCodeLifetime_is_zero()
    {
        var failures = Validate(new AuthorizationServerOptions
        {
            Issuer = "https://auth.example.com",
            AuthorizationEndpoint = { AuthorizationCodeLifetime = TimeSpan.Zero },
        });

        failures.Should().ContainSingle(f => f.Code == "configuration.authorization_endpoint.authorization_code_lifetime.not_positive")
            .Which.Message.Should().Contain("greater than zero");
    }

    [Fact]
    public void Validate_fails_when_AuthorizationCodeLifetime_is_negative()
    {
        var failures = Validate(new AuthorizationServerOptions
        {
            Issuer = "https://auth.example.com",
            AuthorizationEndpoint = { AuthorizationCodeLifetime = -TimeSpan.FromSeconds(1) },
        });

        failures.Should().ContainSingle(f => f.Code == "configuration.authorization_endpoint.authorization_code_lifetime.not_positive")
            .Which.Message.Should().Contain("greater than zero");
    }

    // ── MaxRequestContextBytes ────────────────────────────────────────────────────────────────────

    [Fact]
    public void MaxRequestContextBytes_defaults_to_16_KB()
    {
        new AuthorizationServerOptions().AuthorizationEndpoint.MaxRequestContextBytes.Should().Be(16 * 1024);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    public void Validate_fails_when_MaxRequestContextBytes_is_not_positive(int bytes)
    {
        var failures = Validate(new AuthorizationServerOptions
        {
            Issuer = "https://auth.example.com",
            AuthorizationEndpoint = { MaxRequestContextBytes = bytes },
        });

        failures.Should().ContainSingle(f => f.Code == "configuration.authorization_endpoint.max_request_context_bytes.not_positive")
            .Which.Message.Should().Contain("MaxRequestContextBytes must be greater than zero");
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
        var failures = Validate(new AuthorizationServerOptions
        {
            Issuer = "https://auth.example.com",
            TokenEndpoint = { RefreshTokenLifetime = TimeSpan.FromDays(1) },
        });

        failures.Should().BeEmpty();
    }

    [Fact]
    public void Validate_fails_when_RefreshTokenLifetime_is_zero()
    {
        var failures = Validate(new AuthorizationServerOptions
        {
            Issuer = "https://auth.example.com",
            TokenEndpoint = { RefreshTokenLifetime = TimeSpan.Zero },
        });

        failures.Should().ContainSingle(f => f.Code == "configuration.token_endpoint.refresh_token_lifetime.not_positive")
            .Which.Message.Should().Contain("greater than zero");
    }

    [Fact]
    public void Validate_fails_when_RefreshTokenLifetime_is_negative()
    {
        var failures = Validate(new AuthorizationServerOptions
        {
            Issuer = "https://auth.example.com",
            TokenEndpoint = { RefreshTokenLifetime = -TimeSpan.FromDays(1) },
        });

        failures.Should().ContainSingle(f => f.Code == "configuration.token_endpoint.refresh_token_lifetime.not_positive")
            .Which.Message.Should().Contain("greater than zero");
    }

    // ── AbsoluteFamilyLifetime ────────────────────────────────────────────────────────────────────

    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    public void Validate_fails_when_AbsoluteFamilyLifetime_is_not_positive(int seconds)
    {
        var failures = Validate(new AuthorizationServerOptions
        {
            Issuer = "https://auth.example.com",
            TokenEndpoint = { AbsoluteFamilyLifetime = TimeSpan.FromSeconds(seconds) },
        });

        failures.Should().ContainSingle(f => f.Code == "configuration.token_endpoint.absolute_family_lifetime.not_positive")
            .Which.Message.Should().Contain("AbsoluteFamilyLifetime must be greater than zero");
    }

    [Fact]
    public void Validate_succeeds_when_AbsoluteFamilyLifetime_is_TimeSpan_MaxValue()
    {
        // TimeSpan.MaxValue is the explicit, warned "unbounded" sentinel and remains valid.
        var failures = Validate(new AuthorizationServerOptions
        {
            Issuer = "https://auth.example.com",
            TokenEndpoint = { AbsoluteFamilyLifetime = TimeSpan.MaxValue },
        });

        failures.Should().BeEmpty();
    }

    // ── Cross-field: RefreshTokenLifetime >= AuthorizationCodeLifetime ────────────────────────────

    [Fact]
    public void Validate_fails_when_RefreshTokenLifetime_is_less_than_AuthorizationCodeLifetime()
    {
        var failures = Validate(new AuthorizationServerOptions
        {
            Issuer = "https://auth.example.com",
            AuthorizationEndpoint = { AuthorizationCodeLifetime = TimeSpan.FromSeconds(120) },
            TokenEndpoint = { RefreshTokenLifetime = TimeSpan.FromSeconds(60) },
        });

        failures.Should().ContainSingle(f => f.Code == "configuration.token_endpoint.refresh_token_lifetime.shorter_than_code_lifetime")
            .Which.Message.Should().Contain("RefreshTokenLifetime must be greater than or equal to");
    }

    [Fact]
    public void Validate_succeeds_when_RefreshTokenLifetime_equals_AuthorizationCodeLifetime()
    {
        var failures = Validate(new AuthorizationServerOptions
        {
            Issuer = "https://auth.example.com",
            AuthorizationEndpoint = { AuthorizationCodeLifetime = TimeSpan.FromSeconds(60) },
            TokenEndpoint = { RefreshTokenLifetime = TimeSpan.FromSeconds(60) },
        });

        failures.Should().BeEmpty();
    }

    [Fact]
    public void Validate_succeeds_when_RefreshTokenLifetime_is_greater_than_AuthorizationCodeLifetime()
    {
        var failures = Validate(new AuthorizationServerOptions
        {
            Issuer = "https://auth.example.com",
            AuthorizationEndpoint = { AuthorizationCodeLifetime = TimeSpan.FromSeconds(60) },
            TokenEndpoint = { RefreshTokenLifetime = TimeSpan.FromDays(1) },
        });

        failures.Should().BeEmpty();
    }

    [Fact]
    public void Validate_does_not_emit_cross_field_error_when_RefreshTokenLifetime_is_zero()
    {
        // RefreshTokenLifetime = zero triggers the per-field zero check; the cross-field guard
        // must NOT fire because its condition requires both values to be positive.
        var failures = Validate(new AuthorizationServerOptions
        {
            Issuer = "https://auth.example.com",
            AuthorizationEndpoint = { AuthorizationCodeLifetime = TimeSpan.FromSeconds(60) },
            TokenEndpoint = { RefreshTokenLifetime = TimeSpan.Zero },
        });

        failures.Should().ContainSingle(f => f.Code == "configuration.token_endpoint.refresh_token_lifetime.not_positive")
            .Which.Message.Should().Contain("greater than zero");
    }

    [Fact]
    public void Validate_does_not_emit_cross_field_error_when_AuthorizationCodeLifetime_is_zero()
    {
        // AuthorizationCodeLifetime = zero triggers the per-field zero check; the cross-field guard
        // must NOT fire because its condition requires both values to be positive.
        var failures = Validate(new AuthorizationServerOptions
        {
            Issuer = "https://auth.example.com",
            AuthorizationEndpoint = { AuthorizationCodeLifetime = TimeSpan.Zero },
            TokenEndpoint = { RefreshTokenLifetime = TimeSpan.FromDays(1) },
        });

        failures.Should().ContainSingle(f => f.Code == "configuration.authorization_endpoint.authorization_code_lifetime.not_positive")
            .Which.Message.Should().Contain("AuthorizationCodeLifetime must be greater than zero");
    }

    // ── ClockSkewTolerance — non-negative constraint ─────────────────────────────────────────────

    [Fact]
    public void Validate_fails_when_ClockSkewTolerance_is_negative()
    {
        var failures = Validate(new AuthorizationServerOptions
        {
            Issuer = "https://auth.example.com",
            ClockSkewTolerance = TimeSpan.FromSeconds(-1),
        });

        failures.Should().ContainSingle(f => f.Code == "configuration.clock_skew_tolerance.negative")
            .Which.Message.Should().Contain("ClockSkewTolerance").And.Contain("greater than or equal to zero");
    }

    [Fact]
    public void Validate_succeeds_when_ClockSkewTolerance_is_zero()
    {
        // Zero is a valid strict-mode setting — no skew tolerance at all.
        var failures = Validate(new AuthorizationServerOptions
        {
            Issuer = "https://auth.example.com",
            ClockSkewTolerance = TimeSpan.Zero,
        });

        failures.Should().BeEmpty();
    }

    // ── SigningKeys ──────────────────────────────────────────────────────────────────────────────

    [Fact]
    public void Validate_fails_when_the_signing_key_LeadTime_is_shorter_than_the_JWKS_CacheMaxAge()
    {
        var failures = Validate(new AuthorizationServerOptions
        {
            Issuer = "https://auth.example.com",
            JwksEndpoint = { CacheMaxAge = TimeSpan.FromHours(2) },
            SigningKeys = { LeadTime = TimeSpan.FromHours(2) - TimeSpan.FromSeconds(1) },
        });

        failures.Should().ContainSingle(f => f.Code == "configuration.signing_keys.lead_time.shorter_than_jwks_cache_max_age");
    }

    [Fact]
    public void Validate_accepts_a_signing_key_LeadTime_equal_to_the_JWKS_CacheMaxAge()
    {
        var failures = Validate(new AuthorizationServerOptions
        {
            Issuer = "https://auth.example.com",
            JwksEndpoint = { CacheMaxAge = TimeSpan.FromHours(2) },
            SigningKeys = { LeadTime = TimeSpan.FromHours(2) },
        });

        failures.Should().NotContain(f => f.Code.StartsWith("configuration.signing_keys", StringComparison.Ordinal));
    }

    [Fact]
    public void Validate_fails_with_lead_time_negative_and_not_the_cache_rule_when_LeadTime_is_negative()
    {
        var failures = Validate(new AuthorizationServerOptions
        {
            Issuer = "https://auth.example.com",
            SigningKeys = { LeadTime = TimeSpan.FromSeconds(-1) },
        });

        failures.Where(f => f.Code.StartsWith("configuration.signing_keys", StringComparison.Ordinal))
            .Should().ContainSingle(f => f.Code == "configuration.signing_keys.lead_time.negative");
    }

    [Fact]
    public void Validate_fails_when_RetainRetiredKeysFor_is_negative()
    {
        var failures = Validate(new AuthorizationServerOptions
        {
            Issuer = "https://auth.example.com",
            SigningKeys = { RetainRetiredKeysFor = TimeSpan.FromSeconds(-1) },
        });

        failures.Should().ContainSingle(f => f.Code == "configuration.signing_keys.retain_retired_keys_for.negative");
    }

    // ── ClockSkewTolerance — cross-field: must be < AuthorizationCodeLifetime / 2 ───────────────

    [Fact]
    public void Validate_fails_when_ClockSkewTolerance_equals_half_of_AuthorizationCodeLifetime()
    {
        // The boundary is >=, so exactly half the code lifetime must fail.
        var codeLifetime = TimeSpan.FromSeconds(60);
        var failures = Validate(new AuthorizationServerOptions
        {
            Issuer = "https://auth.example.com",
            AuthorizationEndpoint = { AuthorizationCodeLifetime = codeLifetime },
            ClockSkewTolerance = codeLifetime / 2,
        });

        failures.Should().ContainSingle(f => f.Code == "configuration.clock_skew_tolerance.too_large")
            .Which.Message.Should().Contain("ClockSkewTolerance").And.Contain("half of AuthorizationCodeLifetime");
    }

    [Fact]
    public void Validate_succeeds_when_ClockSkewTolerance_is_one_tick_below_half_of_AuthorizationCodeLifetime()
    {
        // One tick below the boundary must pass.
        var codeLifetime = TimeSpan.FromSeconds(60);
        var failures = Validate(new AuthorizationServerOptions
        {
            Issuer = "https://auth.example.com",
            AuthorizationEndpoint = { AuthorizationCodeLifetime = codeLifetime },
            ClockSkewTolerance = codeLifetime / 2 - TimeSpan.FromTicks(1),
        });

        failures.Should().BeEmpty();
    }

    // ── Simultaneous authorization + token endpoint errors ───────────────────────────────────────

    [Fact]
    public void Validate_accumulates_authorization_endpoint_and_token_endpoint_errors_simultaneously()
    {
        // Both endpoints carry user-info so both produce their own failure, proving both are
        // accumulated in the same result rather than the second short-circuiting the first.
        var failures = Validate(new AuthorizationServerOptions
        {
            Issuer = "https://auth.example.com",
            AuthorizationEndpoint = { Uri = "https://user:pass@auth.example.com/connect/authorize" },
            TokenEndpoint = { Uri = "https://user:pass@auth.example.com/connect/token" },
        });

        failures.Select(f => f.Code).Should().Contain(
        [
            "configuration.authorization_endpoint.uri.userinfo",
            "configuration.token_endpoint.uri.userinfo",
        ]);
    }

    private static void SetGroupProperty(AuthorizationServerOptions options, string propertyPath, string value)
    {
        var parts = propertyPath.Split('.');
        var group = typeof(AuthorizationServerOptions).GetProperty(parts[0])!.GetValue(options)!;
        var prop = group.GetType().GetProperty(parts[1])!;
        prop.SetValue(group, value);
    }

    [Theory]
    [InlineData("auth-error")]                        // no leading slash
    [InlineData("//evil.example.com/error")]          // protocol-relative — an open redirect
    [InlineData("/auth-error?x=1")]                   // query not allowed
    [InlineData("/auth-error#frag")]                  // fragment not allowed
    public void Validate_rejects_malformed_interaction_ErrorPath(string errorPath)
    {
        var failures = Validate(new AuthorizationServerOptions
        {
            Issuer = "https://auth.example.com",
            AuthorizationEndpoint = { Interaction = { ErrorPath = errorPath } },
        });

        failures.Should().ContainSingle(f => f.Code == "configuration.authorization_endpoint.interaction.error_path.unsafe")
            .Which.Message.Should().Contain("Interaction.ErrorPath");
    }

    [Fact]
    public void Validate_accepts_an_absolute_path_ErrorPath()
    {
        var failures = Validate(new AuthorizationServerOptions
        {
            Issuer = "https://auth.example.com",
            AuthorizationEndpoint = { Interaction = { ErrorPath = "/auth-error" } },
        });

        failures.Should().BeEmpty();
    }

    [Theory]
    [InlineData("account/login")]                     // no leading slash
    [InlineData("//evil.example.com/login")]          // protocol-relative — an open redirect
    [InlineData("/\\evil.example.com/login")]         // backslash form of the same
    [InlineData("/account/login?x=1")]                // query not allowed: the framework adds zkd_i
    [InlineData("/account/login#frag")]               // fragment not allowed
    public void Validate_rejects_malformed_interaction_LoginPath(string loginPath)
    {
        var failures = Validate(new AuthorizationServerOptions
        {
            Issuer = "https://auth.example.com",
            AuthorizationEndpoint = { Interaction = { LoginPath = loginPath } },
        });

        failures.Should().ContainSingle(f => f.Code == "configuration.authorization_endpoint.interaction.login_path.unsafe")
            .Which.Message.Should().Contain("Interaction.LoginPath");
    }

    [Theory]
    [InlineData("account/consent")]
    [InlineData("//evil.example.com/consent")]
    [InlineData("/\\evil.example.com/consent")]
    [InlineData("/account/consent?x=1")]
    [InlineData("/account/consent#frag")]
    public void Validate_rejects_malformed_interaction_ConsentPath(string consentPath)
    {
        var failures = Validate(new AuthorizationServerOptions
        {
            Issuer = "https://auth.example.com",
            AuthorizationEndpoint = { Interaction = { ConsentPath = consentPath } },
        });

        failures.Should().ContainSingle(f => f.Code == "configuration.authorization_endpoint.interaction.consent_path.unsafe")
            .Which.Message.Should().Contain("Interaction.ConsentPath");
    }

    [Fact]
    public void Validate_accepts_an_absolute_path_ConsentPath()
    {
        var failures = Validate(new AuthorizationServerOptions
        {
            Issuer = "https://auth.example.com",
            AuthorizationEndpoint = { Interaction = { ConsentPath = "/account/consent" } },
        });

        failures.Should().BeEmpty();
    }

    [Fact]
    public void Validate_accepts_an_absolute_path_LoginPath()
    {
        var failures = Validate(new AuthorizationServerOptions
        {
            Issuer = "https://auth.example.com",
            AuthorizationEndpoint = { Interaction = { LoginPath = "/account/login" } },
        });

        failures.Should().BeEmpty();
    }

    [Theory]
    [InlineData("account/logout")]
    [InlineData("//evil.example.com/logout")]
    [InlineData("/\\evil.example.com/logout")]
    [InlineData("/account/logout?x=1")]
    [InlineData("/account/logout#frag")]
    public void Validate_rejects_malformed_EndSessionEndpoint_LogoutPath(string logoutPath)
    {
        var failures = Validate(new AuthorizationServerOptions
        {
            Issuer = "https://auth.example.com",
            EndSessionEndpoint = { LogoutPath = logoutPath },
        });

        failures.Should().ContainSingle(f => f.Code == "configuration.end_session_endpoint.logout_path.unsafe")
            .Which.Message.Should().Contain("EndSessionEndpoint.LogoutPath");
    }

    [Theory]
    [InlineData("account/signed-out")]
    [InlineData("//evil.example.com/signed-out")]
    [InlineData("/\\evil.example.com/signed-out")]
    [InlineData("/account/signed-out?x=1")]
    [InlineData("/account/signed-out#frag")]
    public void Validate_rejects_malformed_EndSessionEndpoint_SignedOutPath(string signedOutPath)
    {
        var failures = Validate(new AuthorizationServerOptions
        {
            Issuer = "https://auth.example.com",
            EndSessionEndpoint = { SignedOutPath = signedOutPath },
        });

        failures.Should().ContainSingle(f => f.Code == "configuration.end_session_endpoint.signed_out_path.unsafe")
            .Which.Message.Should().Contain("EndSessionEndpoint.SignedOutPath");
    }

    [Fact]
    public void Validate_accepts_absolute_path_end_session_pages()
    {
        var failures = Validate(new AuthorizationServerOptions
        {
            Issuer = "https://auth.example.com",
            EndSessionEndpoint = { LogoutPath = "/account/logout", SignedOutPath = "/account/signed-out" },
        });

        failures.Should().BeEmpty();
    }

    [Theory]
    [InlineData("https://auth.example.com/connect/endsession?x=1", "query component", "configuration.end_session_endpoint.uri.query")]
    [InlineData("https://auth.example.com/connect/endsession#frag", "fragment component", "configuration.end_session_endpoint.uri.fragment")]
    [InlineData("https://user@auth.example.com/connect/endsession", "user information", "configuration.end_session_endpoint.uri.userinfo")]
    public void Validate_rejects_an_EndSessionEndpoint_Uri_its_route_could_not_serve_as_published(string value, string rule, string expectedCode)
    {
        // The route matches on the path alone, so a query published in discovery would reach
        // relying parties and never be honoured.
        var failures = Validate(new AuthorizationServerOptions
        {
            Issuer = "https://auth.example.com",
            EndSessionEndpoint = { Uri = value },
        });

        failures.Should().ContainSingle(f => f.Code == expectedCode)
            .Which.Message.Should().Contain("AuthorizationServerOptions.EndSessionEndpoint.Uri").And.Contain(rule);
    }

    // ── EndSessionEndpoint.Uri — HTTP non-loopback with AllowHttpLoopbackIssuer ──────────────────────

    [Fact]
    public void Validate_fails_for_HTTP_non_loopback_EndSessionEndpoint_override_with_AllowHttpLoopbackIssuer_flag()
    {
        var failures = Validate(new AuthorizationServerOptions
        {
            Issuer = "https://auth.example.com",
            Development = { AllowHttpLoopbackIssuer = true },
            EndSessionEndpoint = { Uri = "http://auth.example.com/connect/endsession" },
        });

        failures.Should().ContainSingle(f => f.Code == "configuration.end_session_endpoint.uri.http_non_loopback")
            .Which.Message.Should().Contain("loopback");
    }

    // ── UserInfoEndpoint.Uri — the same route-matches-on-path-alone rules as JWKS/EndSession ─────

    [Fact]
    public void Validate_fails_when_UserInfoEndpoint_override_is_not_an_absolute_URI()
    {
        var failures = Validate(new AuthorizationServerOptions
        {
            Issuer = "https://auth.example.com",
            UserInfoEndpoint = { Uri = "not-a-uri" },
        });

        failures.Should().ContainSingle(f => f.Code == "configuration.user_info_endpoint.uri.invalid")
            .Which.Message.Should().Contain("Uri");
    }

    [Fact]
    public void Validate_fails_when_UserInfoEndpoint_override_has_user_info()
    {
        var failures = Validate(new AuthorizationServerOptions
        {
            Issuer = "https://auth.example.com",
            UserInfoEndpoint = { Uri = "https://user:pass@auth.example.com/connect/userinfo" },
        });

        failures.Should().ContainSingle(f => f.Code == "configuration.user_info_endpoint.uri.userinfo")
            .Which.Message.Should().Contain("user information");
    }

    [Fact]
    public void Validate_fails_for_HTTP_UserInfoEndpoint_override_without_AllowHttpLoopbackIssuer_flag()
    {
        var failures = Validate(new AuthorizationServerOptions
        {
            Issuer = "https://auth.example.com",
            UserInfoEndpoint = { Uri = "http://auth.example.com/connect/userinfo" },
        });

        failures.Should().ContainSingle(f => f.Code == "configuration.user_info_endpoint.uri.not_https")
            .Which.Message.Should().Contain("HTTPS");
    }

    [Fact]
    public void Validate_fails_for_HTTP_non_loopback_UserInfoEndpoint_override_with_AllowHttpLoopbackIssuer_flag()
    {
        var failures = Validate(new AuthorizationServerOptions
        {
            Issuer = "https://auth.example.com",
            Development = { AllowHttpLoopbackIssuer = true },
            UserInfoEndpoint = { Uri = "http://auth.example.com/connect/userinfo" },
        });

        failures.Should().ContainSingle(f => f.Code == "configuration.user_info_endpoint.uri.http_non_loopback")
            .Which.Message.Should().Contain("loopback");
    }

    [Fact]
    public void Validate_fails_when_UserInfoEndpoint_override_has_different_authority()
    {
        var failures = Validate(new AuthorizationServerOptions
        {
            Issuer = "https://auth.example.com",
            UserInfoEndpoint = { Uri = "https://evil.example.com/connect/userinfo" },
        });

        failures.Should().ContainSingle(f => f.Code == "configuration.user_info_endpoint.uri.authority_mismatch")
            .Which.Message.Should().Contain("same authority");
    }

    [Theory]
    [InlineData("https://auth.example.com/connect/userinfo?foo=bar", "configuration.user_info_endpoint.uri.query")]
    [InlineData("https://auth.example.com/connect/userinfo#fragment", "configuration.user_info_endpoint.uri.fragment")]
    public void Validate_fails_when_UserInfoEndpoint_override_has_query_or_fragment(string value, string expectedCode)
    {
        var failures = Validate(new AuthorizationServerOptions
        {
            Issuer = "https://auth.example.com",
            UserInfoEndpoint = { Uri = value },
        });

        failures.Should().ContainSingle(f => f.Code == expectedCode);
    }

    [Fact]
    public void Validate_succeeds_for_HTTPS_UserInfoEndpoint_override()
    {
        var failures = Validate(new AuthorizationServerOptions
        {
            Issuer = "https://auth.example.com",
            UserInfoEndpoint = { Uri = "https://auth.example.com/connect/userinfo" },
        });

        failures.Should().BeEmpty();
    }
}
