using FluentAssertions;
using ZeeKayDa.Auth.Authorization;
using ZeeKayDa.Auth.Clients;
using ZeeKayDa.Auth.Logging;

namespace ZeeKayDa.Auth.Tests.Authorization;

public class AuthorizeRequestValidatorTests
{
    private const string ClientId = "client-1";
    private const string RedirectUri = "https://app.example.com/callback";

    // A syntactically valid S256 challenge: 43 unreserved characters.
    private const string Challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

    // ── Phase 1: local errors, never redirected ───────────────────────────────────────────────

    [Theory]
    [InlineData("client_id")]
    [InlineData("redirect_uri")]
    public async Task Phase1_missing_client_id_or_redirect_uri_is_a_local_error(string missing)
    {
        var parameters = ValidParameters();
        parameters.Remove(missing);

        var result = await Validate(parameters);

        result.Should().BeOfType<AuthorizeRequestValidationResult.LocalError>();
    }

    [Fact]
    public async Task Phase1_unknown_client_is_a_local_error()
    {
        var parameters = ValidParameters(clientId: "no-such-client");

        var result = await Validate(parameters);

        result.Should().BeOfType<AuthorizeRequestValidationResult.LocalError>();
    }

    [Fact]
    public async Task Phase1_unknown_client_and_unregistered_redirect_produce_identical_errors()
    {
        var unknownClient = await Validate(ValidParameters(clientId: "no-such-client"));
        var badRedirect = await Validate(ValidParameters(redirectUri: "https://evil.example.com/cb"));

        var a = unknownClient.Should().BeOfType<AuthorizeRequestValidationResult.LocalError>().Subject;
        var b = badRedirect.Should().BeOfType<AuthorizeRequestValidationResult.LocalError>().Subject;
        (a.Error, a.Description).Should().Be((b.Error, b.Description),
            "distinguishable phase-1 errors would be a client-enumeration oracle");
    }

    [Theory]
    [InlineData("https://app.example.com/other")]              // unregistered path
    [InlineData("https://app.example.com/callback#fragment")]  // fragment never allowed
    [InlineData("https://app.example.com:444/callback")]       // port variance only for loopback
    [InlineData("relative/path")]                              // not absolute
    [InlineData("")]                                           // empty
    public async Task Phase1_redirect_uri_not_exactly_matching_registration_is_a_local_error(string redirectUri)
    {
        var result = await Validate(ValidParameters(redirectUri: redirectUri));

        result.Should().BeOfType<AuthorizeRequestValidationResult.LocalError>();
    }

    [Fact]
    public async Task Phase1_duplicated_client_id_is_a_local_error()
    {
        var parameters = ValidParameters();
        parameters["client_id"] = [ClientId, ClientId];

        var result = await Validate(parameters);

        result.Should().BeOfType<AuthorizeRequestValidationResult.LocalError>();
    }

    [Fact]
    public async Task Phase1_loopback_redirect_may_vary_its_port()
    {
        var client = Client() with
        {
            RedirectUris = new HashSet<string>(StringComparer.Ordinal) { "http://127.0.0.1/cb" },
        };
        var parameters = ValidParameters(redirectUri: "http://127.0.0.1:49152/cb");

        var result = await Validate(parameters, client);

        result.Should().BeOfType<AuthorizeRequestValidationResult.Valid>(
            "RFC 8252 §7.3 requires accepting a variable port on loopback redirects");
    }

    [Fact]
    public async Task Phase1_non_loopback_registration_gets_no_port_variance()
    {
        var client = Client() with
        {
            RedirectUris = new HashSet<string>(StringComparer.Ordinal) { "http://127.0.0.1/cb" },
        };
        var parameters = ValidParameters(redirectUri: "http://localhost.attacker.com:49152/cb");

        var result = await Validate(parameters, client);

        result.Should().BeOfType<AuthorizeRequestValidationResult.LocalError>();
    }

    // ── Phase 2: errors redirect to the validated client ──────────────────────────────────────

    [Fact]
    public async Task Phase2_duplicated_parameter_is_invalid_request()
    {
        var parameters = ValidParameters();
        parameters["nonce"] = ["n-1", "n-2"];

        var result = await Validate(parameters);

        var error = result.Should().BeOfType<AuthorizeRequestValidationResult.RedirectError>().Subject;
        error.Error.Should().Be("invalid_request");
        error.RedirectUri.Should().Be(RedirectUri);
    }

    [Theory]
    [InlineData("request", "request_not_supported")]
    [InlineData("request_uri", "request_uri_not_supported")]
    public async Task Phase2_jar_and_par_parameters_are_refused(string parameter, string expectedError)
    {
        var parameters = ValidParameters();
        parameters[parameter] = ["anything"];

        var result = await Validate(parameters);

        result.Should().BeOfType<AuthorizeRequestValidationResult.RedirectError>()
            .Subject.Error.Should().Be(expectedError);
    }

    [Theory]
    [InlineData(null, "invalid_request")]
    [InlineData("token", "unsupported_response_type")]
    [InlineData("id_token", "unsupported_response_type")]
    [InlineData("code token", "unsupported_response_type")]
    public async Task Phase2_response_type_must_be_code(string? responseType, string expectedError)
    {
        var parameters = ValidParameters();
        if (responseType is null)
            parameters.Remove("response_type");
        else
            parameters["response_type"] = [responseType];

        var result = await Validate(parameters);

        result.Should().BeOfType<AuthorizeRequestValidationResult.RedirectError>()
            .Subject.Error.Should().Be(expectedError);
    }

    [Fact]
    public async Task Phase2_client_without_authorization_code_grant_is_unauthorized_client()
    {
        var client = Client() with { AllowedGrantTypes = new HashSet<GrantType> { GrantType.RefreshToken } };

        var result = await Validate(ValidParameters(), client);

        result.Should().BeOfType<AuthorizeRequestValidationResult.RedirectError>()
            .Subject.Error.Should().Be("unauthorized_client");
    }

    [Theory]
    [InlineData("form_post")]
    [InlineData("fragment")]
    public async Task Phase2_non_query_response_modes_are_refused(string responseMode)
    {
        var parameters = ValidParameters();
        parameters["response_mode"] = [responseMode];

        var result = await Validate(parameters);

        result.Should().BeOfType<AuthorizeRequestValidationResult.RedirectError>()
            .Subject.Error.Should().Be("invalid_request");
    }

    [Fact]
    public async Task Phase2_explicit_query_response_mode_is_accepted()
    {
        var parameters = ValidParameters();
        parameters["response_mode"] = ["query"];

        var result = await Validate(parameters);

        result.Should().BeOfType<AuthorizeRequestValidationResult.Valid>();
    }

    [Theory]
    [InlineData(null)]
    [InlineData("profile email")] // no openid
    public async Task Phase2_scope_without_openid_is_invalid_scope(string? scope)
    {
        var parameters = ValidParameters();
        if (scope is null)
            parameters.Remove("scope");
        else
            parameters["scope"] = [scope];

        var result = await Validate(parameters);

        result.Should().BeOfType<AuthorizeRequestValidationResult.RedirectError>()
            .Subject.Error.Should().Be("invalid_scope");
    }

    [Fact]
    public async Task Phase2_openid_dropped_by_narrowing_is_invalid_scope()
    {
        var client = Client() with
        {
            AllowedScopes = new HashSet<string>(StringComparer.Ordinal) { "profile" },
        };

        var result = await Validate(ValidParameters(), client);

        result.Should().BeOfType<AuthorizeRequestValidationResult.RedirectError>()
            .Subject.Error.Should().Be("invalid_scope");
    }

    [Fact]
    public async Task Phase2_disallowed_scopes_are_silently_narrowed()
    {
        var parameters = ValidParameters();
        parameters["scope"] = ["openid profile admin"];

        var result = await Validate(parameters);

        var valid = result.Should().BeOfType<AuthorizeRequestValidationResult.Valid>().Subject;
        // RFC 6749 §3.3 permits partially ignoring the requested scope; the granted set is
        // reported via the token response's scope parameter, not an error.
        valid.Request.Scopes.Should().Equal("openid", "profile");
    }

    [Fact]
    public async Task Phase2_missing_nonce_is_invalid_request()
    {
        var parameters = ValidParameters();
        parameters.Remove("nonce");

        var result = await Validate(parameters);

        result.Should().BeOfType<AuthorizeRequestValidationResult.RedirectError>()
            .Subject.Error.Should().Be("invalid_request");
    }

    [Theory]
    [InlineData(null)]                 // missing entirely
    [InlineData("short")]              // under 43 chars
    [InlineData("contains spaces contains spaces contains spaces")]
    public async Task Phase2_missing_or_malformed_code_challenge_is_invalid_request(string? challenge)
    {
        var parameters = ValidParameters();
        if (challenge is null)
            parameters.Remove("code_challenge");
        else
            parameters["code_challenge"] = [challenge];

        var result = await Validate(parameters);

        result.Should().BeOfType<AuthorizeRequestValidationResult.RedirectError>()
            .Subject.Error.Should().Be("invalid_request");
    }

    [Theory]
    [InlineData(null)]     // absent — the plain default of RFC 7636 is refused, not assumed
    [InlineData("plain")]
    [InlineData("s256")]   // case-sensitive
    public async Task Phase2_code_challenge_method_must_be_S256(string? method)
    {
        var parameters = ValidParameters();
        if (method is null)
            parameters.Remove("code_challenge_method");
        else
            parameters["code_challenge_method"] = [method];

        var result = await Validate(parameters);

        result.Should().BeOfType<AuthorizeRequestValidationResult.RedirectError>()
            .Subject.Error.Should().Be("invalid_request");
    }

    [Fact]
    public async Task Phase2_prompt_none_combined_with_other_values_is_invalid_request()
    {
        var parameters = ValidParameters();
        parameters["prompt"] = ["none login"];

        var result = await Validate(parameters);

        result.Should().BeOfType<AuthorizeRequestValidationResult.RedirectError>()
            .Subject.Error.Should().Be("invalid_request");
    }

    [Fact]
    public async Task Phase2_unrecognised_prompt_values_are_ignored()
    {
        var parameters = ValidParameters();
        parameters["prompt"] = ["login future_value"];

        var result = await Validate(parameters);

        var valid = result.Should().BeOfType<AuthorizeRequestValidationResult.Valid>().Subject;
        valid.Request.Prompts.Should().Equal(PromptValue.Login);
    }

    [Fact]
    public async Task Phase2_prompt_value_outside_client_allowlist_is_invalid_request()
    {
        var client = Client() with
        {
            AllowedPromptValues = new HashSet<PromptValue> { PromptValue.Login },
        };
        var parameters = ValidParameters();
        parameters["prompt"] = ["consent"];

        var result = await Validate(parameters, client);

        result.Should().BeOfType<AuthorizeRequestValidationResult.RedirectError>()
            .Subject.Error.Should().Be("invalid_request");
    }

    [Theory]
    [InlineData("-1")]
    [InlineData("abc")]
    [InlineData("1.5")]
    public async Task Phase2_malformed_max_age_is_invalid_request(string maxAge)
    {
        var parameters = ValidParameters();
        parameters["max_age"] = [maxAge];

        var result = await Validate(parameters);

        result.Should().BeOfType<AuthorizeRequestValidationResult.RedirectError>()
            .Subject.Error.Should().Be("invalid_request");
    }

    [Fact]
    public async Task Phase2_errors_echo_state_when_present()
    {
        var parameters = ValidParameters();
        parameters["state"] = ["opaque-client-state"];
        parameters.Remove("nonce");

        var result = await Validate(parameters);

        result.Should().BeOfType<AuthorizeRequestValidationResult.RedirectError>()
            .Subject.State.Should().Be("opaque-client-state");
    }

    [Fact]
    public async Task Phase2_unknown_parameters_are_ignored()
    {
        var parameters = ValidParameters();
        parameters["ui_locales"] = ["en-GB"];

        var result = await Validate(parameters);

        result.Should().BeOfType<AuthorizeRequestValidationResult.Valid>();
    }

    // ── Valid request ─────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task Valid_request_carries_all_validated_values()
    {
        var parameters = ValidParameters();
        parameters["state"] = ["opaque-client-state"];
        parameters["max_age"] = ["300"];

        var result = await Validate(parameters);

        var valid = result.Should().BeOfType<AuthorizeRequestValidationResult.Valid>().Subject;
        valid.Request.Client.ClientId.Should().Be(ClientId);
        valid.Request.RedirectUri.Should().Be(RedirectUri);
        valid.Request.Scopes.Should().Equal("openid", "profile");
        valid.Request.State.Should().Be("opaque-client-state");
        valid.Request.Nonce.Should().Be("n-0S6_WzA2Mj");
        valid.Request.CodeChallenge.Should().Be(Challenge);
        valid.Request.CodeChallengeMethod.Should().Be(CodeChallengeMethod.S256);
        valid.Request.MaxAge.Should().Be(TimeSpan.FromSeconds(300));
    }

    // ── Fixture ───────────────────────────────────────────────────────────────────────────────

    private static ClientRegistration Client() =>
        ClientRegistration.CreatePublic(
            ClientId,
            redirectUris: [RedirectUri],
            postLogoutRedirectUris: [],
            allowedScopes: ["openid", "profile"]);

    private static Dictionary<string, IReadOnlyList<string?>> ValidParameters(
        string clientId = ClientId,
        string redirectUri = RedirectUri) =>
        new(StringComparer.Ordinal)
        {
            ["client_id"] = [clientId],
            ["redirect_uri"] = [redirectUri],
            ["response_type"] = ["code"],
            ["scope"] = ["openid profile"],
            ["nonce"] = ["n-0S6_WzA2Mj"],
            ["code_challenge"] = [Challenge],
            ["code_challenge_method"] = ["S256"],
        };

    private static async Task<AuthorizeRequestValidationResult> Validate(
        Dictionary<string, IReadOnlyList<string?>> parameters,
        ClientRegistration? client = null)
    {
        var resolver = new ValidatedClientResolver(
            new SingleClientRepository(client ?? Client()),
            new PassingValidator(),
            NullSanitizingLogger<ValidatedClientResolver>.Instance);
        var validator = new AuthorizeRequestValidator(resolver);

        return await validator.ValidateAsync(parameters, TestContext.Current.CancellationToken);
    }

    private sealed class SingleClientRepository(IClientRegistration client) : IClientRepository
    {
        public ValueTask<IClientRegistration?> FindByClientIdAsync(
            string clientId, CancellationToken cancellationToken = default) =>
            ValueTask.FromResult(string.Equals(clientId, client.ClientId, StringComparison.Ordinal)
                ? (IClientRegistration?)client
                : null);
    }

    private sealed class PassingValidator : IClientRegistrationValidator
    {
        public void Validate(IClientRegistration client)
        {
            // These tests exercise request validation; registration validation has its own suite.
        }
    }

    private sealed class NullSanitizingLogger<T> : ISanitizingLogger<T>
    {
        public static readonly NullSanitizingLogger<T> Instance = new();

        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;
        public bool IsEnabled(Microsoft.Extensions.Logging.LogLevel logLevel) => false;
        public void Log<TState>(
            Microsoft.Extensions.Logging.LogLevel logLevel,
            Microsoft.Extensions.Logging.EventId eventId,
            TState state,
            Exception? exception,
            Func<TState, Exception?, string> formatter)
        {
        }
    }
}
