using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using ZeeKayDa.Auth;
using ZeeKayDa.Auth.Authorization;
using ZeeKayDa.Auth.Clients;
using ZeeKayDa.Auth.Configuration;
using ZeeKayDa.Auth.Logging;
using ZeeKayDa.Auth.Tests.Tokens;
using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.Tests.Clients;

public sealed class ClientRegistrationValidatorTests
{
    // ── Fake/helper infrastructure ────────────────────────────────────────────────────────────────

    private sealed class FakeSecret : IClientSecret { }

    private sealed class AnySecret : IClientSecret { }

    /// <summary>
    /// A hasher that accepts any credential of type <see cref="FakeSecret"/> and always returns
    /// the configured <paramref name="verifyResult"/> from <c>Verify</c>.
    /// </summary>
    private sealed class FakeHasher : IClientSecretHasher
    {
        private readonly bool _verifyResult;

        public FakeHasher(bool verifyResult = false) => _verifyResult = verifyResult;

        public bool CanHandle(IClientSecret secret) => secret is FakeSecret;

        public bool Verify(IClientSecret stored, ReadOnlySpan<char> presented)
            => _verifyResult;

        public IClientSecret Create(ReadOnlySpan<char> plaintext) => new FakeSecret();
    }

    /// <summary>A hasher that handles <see cref="AnySecret"/> and always returns false.</summary>
    private sealed class FallbackHasher : IClientSecretHasher
    {
        public bool CanHandle(IClientSecret secret) => secret is AnySecret;
        public bool Verify(IClientSecret stored, ReadOnlySpan<char> presented) => false;
        public IClientSecret Create(ReadOnlySpan<char> plaintext) => new AnySecret();
    }

    /// <summary>
    /// A logger that records LogWarning calls for assertion.
    /// </summary>
    private sealed class CapturingLogger : ISanitizingLogger<ClientRegistrationValidator>
    {
        private readonly List<string> _warnings = new();

        public IReadOnlyList<string> Warnings => _warnings;

        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;
        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(
            LogLevel logLevel,
            EventId eventId,
            TState state,
            Exception? exception,
            Func<TState, Exception?, string> formatter)
        {
            if (logLevel == LogLevel.Warning)
                _warnings.Add(formatter(state, exception));
        }
    }

    private static CompositeClientSecretHasher MakeHasher(IClientSecretHasher hasher)
        => new CompositeClientSecretHasher(
            [hasher],
            Options.Create(new ClientSecretHasherRegistrationOptions()));

    private static ClientRegistrationValidator MakeValidator(
        IClientSecretHasher? hasher = null,
        ISanitizingLogger<ClientRegistrationValidator>? logger = null,
        AuthorizationServerOptions? serverOptions = null,
        SigningKeySet? keySet = null,
        bool withKeyRing = true)
    {
        var opts = serverOptions ?? BuildDefaultServerOptions();

        var composite = MakeHasher(hasher ?? new FakeHasher());
        return new ClientRegistrationValidator(
            Options.Create(opts),
            composite,
            logger ?? NullSanitizingLogger<ClientRegistrationValidator>.Instance,
            withKeyRing ? new FakeSigningKeyRing(keySet) : null);
    }

    /// <summary>
    /// A ring whose <c>CurrentOrNull</c> is whatever the test supplies — <see langword="null"/>
    /// standing for a ring that has not yet read its source.
    /// </summary>
    private sealed class FakeSigningKeyRing(SigningKeySet? current) : ISigningKeyRing
    {
        public SigningKeySet Current => current ?? throw new InvalidOperationException();

        public ValueTask<SigningOutcome> SignAsync<TState>(
            TState state,
            Func<SigningContext, TState, ReadOnlyMemory<byte>> buildSigningInput,
            CancellationToken cancellationToken = default)
            => throw new NotSupportedException();

        ValueTask ISigningKeyRing.EnsureInitializedAsync(CancellationToken cancellationToken)
            => throw new NotSupportedException();

        SigningKeySet? ISigningKeyRing.CurrentOrNull => current;
    }

    private static AuthorizationServerOptions BuildDefaultServerOptions()
    {
        var opts = new AuthorizationServerOptions { Issuer = "https://test.example.com" };
        // Include "none" so public clients (AllowedTokenEndpointAuthMethods={"none"}) pass
        // the subset check. Confidential clients use "client_secret_basic" which is already default.
        opts.TokenEndpoint.AuthMethodsSupported.Add(TokenEndpointAuthMethods.None);
        return opts;
    }

    private static ClientRegistration MakeValidPublicClient(string clientId = "test-client") =>
        ClientRegistration.CreatePublic(
            clientId,
            ["https://app.example.com/callback"],
            [],
            ["openid"]);

    private static ClientRegistration MakeValidConfidentialClient(
        string clientId = "test-client",
        IClientSecret? secret = null) =>
        ClientRegistration.CreateConfidential(
            clientId,
            secret ?? new FakeSecret(),
            ["https://app.example.com/callback"],
            [],
            ["openid"]);

    // ── Valid clients pass ────────────────────────────────────────────────────────────────────────

    [Fact]
    public void Validate_does_not_throw_for_valid_public_client()
    {
        var validator = MakeValidator();
        var client = MakeValidPublicClient();

        var act = () => validator.Validate(client);

        act.Should().NotThrow();
    }

    [Fact]
    public void Validate_does_not_throw_for_valid_confidential_client()
    {
        var validator = MakeValidator();
        var client = MakeValidConfidentialClient();

        var act = () => validator.Validate(client);

        act.Should().NotThrow();
    }

    // ── Redirect URI rules ────────────────────────────────────────────────────────────────────────

    [Fact]
    public void Validate_passes_for_HTTPS_redirect_uri()
    {
        var validator = MakeValidator();
        var client = MakeValidPublicClient() with
        {
            RedirectUris = new HashSet<string>(["https://app.example.com/callback"], StringComparer.Ordinal)
        };

        var act = () => validator.Validate(client);

        act.Should().NotThrow();
    }

    [Fact]
    public void Validate_passes_for_HTTP_loopback_redirect_uri()
    {
        var validator = MakeValidator();
        var client = MakeValidPublicClient() with
        {
            RedirectUris = new HashSet<string>(["http://127.0.0.1/callback"], StringComparer.Ordinal)
        };

        var act = () => validator.Validate(client);

        act.Should().NotThrow();
    }

    [Fact]
    public void Validate_passes_for_HTTP_IPv6_loopback_redirect_uri()
    {
        var validator = MakeValidator();
        var client = MakeValidPublicClient() with
        {
            RedirectUris = new HashSet<string>(["http://[::1]/cb"], StringComparer.Ordinal)
        };

        var act = () => validator.Validate(client);

        act.Should().NotThrow();
    }

    [Fact]
    public void Validate_passes_for_private_use_scheme_with_dot()
    {
        var validator = MakeValidator();
        var client = MakeValidPublicClient() with
        {
            RedirectUris = new HashSet<string>(["myapp.scheme://callback"], StringComparer.Ordinal)
        };

        var act = () => validator.Validate(client);

        act.Should().NotThrow();
    }

    [Fact]
    public void Validate_fails_with_fragment_code_if_redirect_uri_has_fragment()
    {
        var validator = MakeValidator();
        var client = MakeValidPublicClient() with
        {
            RedirectUris = new HashSet<string>(["https://app.example.com/cb#x"], StringComparer.Ordinal)
        };

        var act = () => validator.Validate(client);

        act.Should().Throw<ZeeKayDaConfigurationException>()
            .Which.AggregatedFailures.Should().Contain(f => f.Code == "client.redirect_uri.fragment");
    }

    [Fact]
    public void Validate_fails_with_user_info_code_if_redirect_uri_has_user_info()
    {
        var validator = MakeValidator();
        var client = MakeValidPublicClient() with
        {
            RedirectUris = new HashSet<string>(["https://user@app.example.com/cb"], StringComparer.Ordinal)
        };

        var act = () => validator.Validate(client);

        act.Should().Throw<ZeeKayDaConfigurationException>()
            .Which.AggregatedFailures.Should().Contain(f => f.Code == "client.redirect_uri.userinfo");
    }

    [Fact]
    public void Validate_fails_with_scheme_not_allowed_code_if_redirect_uri_uses_javascript_scheme()
    {
        var validator = MakeValidator();
        var client = MakeValidPublicClient() with
        {
            RedirectUris = new HashSet<string>(["javascript:alert(1)"], StringComparer.Ordinal)
        };

        var act = () => validator.Validate(client);

        act.Should().Throw<ZeeKayDaConfigurationException>()
            .Which.AggregatedFailures.Should().Contain(f => f.Code == "client.redirect_uri.scheme_not_allowed");
    }

    [Fact]
    public void Validate_fails_with_scheme_http_non_loopback_code_if_redirect_uri_uses_HTTP_on_non_loopback()
    {
        var validator = MakeValidator();
        var client = MakeValidPublicClient() with
        {
            RedirectUris = new HashSet<string>(["http://attacker.com/cb"], StringComparer.Ordinal)
        };

        var act = () => validator.Validate(client);

        act.Should().Throw<ZeeKayDaConfigurationException>()
            .Which.AggregatedFailures.Should().Contain(f => f.Code == "client.redirect_uri.scheme_http_non_loopback");
    }

    [Fact]
    public void Validate_emits_log_warning_for_localhost_redirect_uri()
    {
        var logger = new CapturingLogger();
        var validator = MakeValidator(logger: logger);
        var client = MakeValidPublicClient() with
        {
            RedirectUris = new HashSet<string>(["http://localhost/callback"], StringComparer.Ordinal)
        };

        validator.Validate(client);

        logger.Warnings.Should().ContainSingle(w => w.Contains("localhost"));
    }

    [Fact]
    public void Validate_fails_with_fragment_code_and_suppresses_localhost_warning_for_localhost_uri_with_fragment()
    {
        // The localhost advisory warning is noise when the URI is already being rejected for another
        // reason. A localhost URI carrying a fragment must produce the fragment failure but NOT the
        // localhost warning.
        var logger = new CapturingLogger();
        var validator = MakeValidator(logger: logger);
        var client = MakeValidPublicClient() with
        {
            RedirectUris = new HashSet<string>(["http://localhost/cb#frag"], StringComparer.Ordinal)
        };

        var act = () => validator.Validate(client);

        act.Should().Throw<ZeeKayDaConfigurationException>()
            .Which.AggregatedFailures.Should().Contain(f => f.Code == "client.redirect_uri.fragment");
        logger.Warnings.Should().NotContain(w => w.Contains("localhost"));
    }

    [Fact]
    public void Validate_fails_with_scheme_http_non_loopback_code_for_localhost_attacker_subdomain()
    {
        var validator = MakeValidator();
        var client = MakeValidPublicClient() with
        {
            RedirectUris = new HashSet<string>(["http://localhost.attacker.com/cb"], StringComparer.Ordinal)
        };

        var act = () => validator.Validate(client);

        act.Should().Throw<ZeeKayDaConfigurationException>()
            .Which.AggregatedFailures.Should().Contain(f => f.Code == "client.redirect_uri.scheme_http_non_loopback");
    }

    [Fact]
    public void Validate_fails_with_IPv6_zone_id_code_for_HTTP_IPv6_with_zone_id()
    {
        var validator = MakeValidator();
        var client = MakeValidPublicClient() with
        {
            // Zone IDs on loopback interfaces should not be trusted
            RedirectUris = new HashSet<string>(["http://[::1%25eth0]/cb"], StringComparer.Ordinal)
        };

        var act = () => validator.Validate(client);

        act.Should().Throw<ZeeKayDaConfigurationException>()
            .Which.AggregatedFailures.Should().Contain(f => f.Code == "client.redirect_uri.ipv6_zone_id");
    }

    [Fact]
    public void Validate_fails_with_IPv6_zone_id_code_for_HTTPS_IPv6_with_zone_id()
    {
        // The zone-ID check must be scheme-neutral: an https:// URI with a zone ID would otherwise
        // pass IsSchemeAllowed (it is https) and slip through.
        var validator = MakeValidator();
        var client = MakeValidPublicClient() with
        {
            RedirectUris = new HashSet<string>(["https://[::1%25eth0]/cb"], StringComparer.Ordinal)
        };

        var act = () => validator.Validate(client);

        act.Should().Throw<ZeeKayDaConfigurationException>()
            .Which.AggregatedFailures.Should().Contain(f => f.Code == "client.redirect_uri.ipv6_zone_id");
    }

    [Fact]
    public void Validate_passes_but_emits_log_warning_for_HTTPS_localhost_redirect_uri()
    {
        // The localhost advisory warning (RFC 8252 §8.3) must be scheme-neutral: it fires for any
        // passing URI whose host is 'localhost', including https://localhost.
        var logger = new CapturingLogger();
        var validator = MakeValidator(logger: logger);
        var client = MakeValidPublicClient() with
        {
            RedirectUris = new HashSet<string>(["https://localhost/cb"], StringComparer.Ordinal)
        };

        var act = () => validator.Validate(client);

        act.Should().NotThrow();
        logger.Warnings.Should().ContainSingle(w => w.Contains("localhost"));
    }

    [Fact]
    public void Validate_does_not_normalize_percent_encoded_URI()
    {
        // Percent-encoded URIs are valid as-is — no normalisation applied
        var validator = MakeValidator();
        var client = MakeValidPublicClient() with
        {
            RedirectUris = new HashSet<string>(["https://app.example.com/cb%20x"], StringComparer.Ordinal)
        };

        var act = () => validator.Validate(client);

        act.Should().NotThrow();
    }

    [Fact]
    public void Validate_fails_with_path_traversal_code_if_redirect_uri_has_path_traversal()
    {
        var validator = MakeValidator();
        var client = MakeValidPublicClient() with
        {
            RedirectUris = new HashSet<string>(["https://app.example.com/../cb"], StringComparer.Ordinal)
        };

        var act = () => validator.Validate(client);

        act.Should().Throw<ZeeKayDaConfigurationException>()
            .Which.AggregatedFailures.Should().Contain(f => f.Code == "client.redirect_uri.path_traversal");
    }

    [Fact]
    public void Validate_fails_with_path_traversal_code_for_path_traversal_with_query_suffix()
    {
        // The query suffix must be stripped before splitting; otherwise the final segment is
        // "..?x=1", which would not match ".." and would slip past the check.
        var validator = MakeValidator();
        var client = MakeValidPublicClient() with
        {
            RedirectUris = new HashSet<string>(["https://app/cb/..?x=1"], StringComparer.Ordinal)
        };

        var act = () => validator.Validate(client);

        act.Should().Throw<ZeeKayDaConfigurationException>()
            .Which.AggregatedFailures.Should().Contain(f => f.Code == "client.redirect_uri.path_traversal");
    }

    [Fact]
    public void Validate_fails_with_path_traversal_code_for_path_traversal_with_mixed_percent_encoding()
    {
        // ".%2e" decodes to ".." but neither literal nor whole-segment %2e%2e matching catches it;
        // per-segment percent-decoding does.
        var validator = MakeValidator();
        var client = MakeValidPublicClient() with
        {
            RedirectUris = new HashSet<string>(["https://app/cb/.%2e/x"], StringComparer.Ordinal)
        };

        var act = () => validator.Validate(client);

        act.Should().Throw<ZeeKayDaConfigurationException>()
            .Which.AggregatedFailures.Should().Contain(f => f.Code == "client.redirect_uri.path_traversal");
    }

    [Fact]
    public void Validate_fails_with_path_traversal_code_for_private_use_single_slash_path_traversal()
    {
        // RFC 8252 §7.1 private-use scheme in its canonical single-slash form (scheme:/path) has no
        // "://" authority, so traversal scanning must handle the ":/" form too.
        var validator = MakeValidator();
        var client = MakeValidPublicClient() with
        {
            RedirectUris = new HashSet<string>(["com.example.app:/cb/../x"], StringComparer.Ordinal)
        };

        var act = () => validator.Validate(client);

        act.Should().Throw<ZeeKayDaConfigurationException>()
            .Which.AggregatedFailures.Should().Contain(f => f.Code == "client.redirect_uri.path_traversal");
    }

    [Fact]
    public void Validate_does_not_false_flag_zone_id_for_query_with_bracketed_percent_encoding()
    {
        // A percent-encoded '%' inside brackets in the query (e.g. "?a=[b%25c]") must not be parsed
        // as an IPv6 zone ID: authority parsing must stop at the '?'.
        var validator = MakeValidator();
        var client = MakeValidPublicClient() with
        {
            RedirectUris = new HashSet<string>(["https://example.com?a=[b%25c]"], StringComparer.Ordinal)
        };

        var act = () => validator.Validate(client);

        act.Should().NotThrow();
    }

    [Fact]
    public void Validate_fails_with_count_exceeded_code_if_more_than_32_redirect_uris()
    {
        var validator = MakeValidator();
        var uris = Enumerable.Range(1, 33)
            .Select(i => $"https://app.example.com/cb{i}")
            .ToHashSet(StringComparer.Ordinal);
        var client = MakeValidPublicClient() with { RedirectUris = uris };

        var act = () => validator.Validate(client);

        act.Should().Throw<ZeeKayDaConfigurationException>()
            .Which.AggregatedFailures.Should().Contain(f => f.Code == "client.redirect_uri.count_exceeded");
    }

    [Fact]
    public void Validate_fails_with_fragment_code_if_post_logout_redirect_uri_has_fragment()
    {
        var validator = MakeValidator();
        var client = MakeValidPublicClient() with
        {
            PostLogoutRedirectUris = new HashSet<string>(
                ["https://app.example.com/logout#frag"], StringComparer.Ordinal)
        };

        var act = () => validator.Validate(client);

        act.Should().Throw<ZeeKayDaConfigurationException>()
            .Which.AggregatedFailures.Should().Contain(f => f.Code == "client.redirect_uri.fragment");
    }

    [Fact]
    public void Validate_fails_with_count_exceeded_code_if_more_than_32_post_logout_redirect_uris()
    {
        var validator = MakeValidator();
        var uris = Enumerable.Range(1, 33)
            .Select(i => $"https://app.example.com/logout{i}")
            .ToHashSet(StringComparer.Ordinal);
        var client = MakeValidPublicClient() with { PostLogoutRedirectUris = uris };

        var act = () => validator.Validate(client);

        act.Should().Throw<ZeeKayDaConfigurationException>()
            .Which.AggregatedFailures.Should().Contain(f => f.Code == "client.redirect_uri.count_exceeded");
    }

    // ── IsPublic trinity ──────────────────────────────────────────────────────────────────────────

    [Fact]
    public void Validate_passes_for_public_client_with_no_credentials_and_none_auth_method()
    {
        var validator = MakeValidator();
        var client = ClientRegistration.CreatePublic(
            "client",
            ["https://app.example.com/cb"],
            [],
            ["openid"]);

        var act = () => validator.Validate(client);

        act.Should().NotThrow();
    }

    [Fact]
    public void Validate_passes_for_confidential_client_with_secret_and_ClientSecretBasic_auth_method()
    {
        var validator = MakeValidator();
        var client = ClientRegistration.CreateConfidential(
            "client",
            new FakeSecret(),
            ["https://app.example.com/cb"],
            [],
            ["openid"]);

        var act = () => validator.Validate(client);

        act.Should().NotThrow();
    }

    [Fact]
    public void Validate_fails_with_trinity_violation_code_if_IsPublic_is_true_but_has_credential()
    {
        var validator = MakeValidator();
        var client = new ClientRegistration
        {
            ClientId = "client",
            Credentials = [new FakeSecret()],
            IsPublic = true,
            RedirectUris = new HashSet<string>(["https://app.example.com/cb"], StringComparer.Ordinal),
            PostLogoutRedirectUris = new HashSet<string>(StringComparer.Ordinal),
            AllowedTokenEndpointAuthMethods = new HashSet<string>(
                [TokenEndpointAuthMethods.None], StringComparer.Ordinal)
        };

        var act = () => validator.Validate(client);

        act.Should().Throw<ZeeKayDaConfigurationException>()
            .Which.AggregatedFailures.Should().Contain(f => f.Code == "client.is_public.trinity_violation");
    }

    [Fact]
    public void Validate_fails_with_trinity_violation_code_if_IsPublic_is_false_with_no_credentials_and_ClientSecretBasic()
    {
        var validator = MakeValidator();
        var client = new ClientRegistration
        {
            ClientId = "client",
            Credentials = [],
            IsPublic = false,
            RedirectUris = new HashSet<string>(["https://app.example.com/cb"], StringComparer.Ordinal),
            PostLogoutRedirectUris = new HashSet<string>(StringComparer.Ordinal),
            AllowedTokenEndpointAuthMethods = new HashSet<string>(
                [TokenEndpointAuthMethods.ClientSecretBasic], StringComparer.Ordinal)
        };

        var act = () => validator.Validate(client);

        act.Should().Throw<ZeeKayDaConfigurationException>()
            .Which.AggregatedFailures.Should().Contain(f => f.Code == "client.is_public.trinity_violation");
    }

    [Fact]
    public void Validate_fails_with_trinity_violation_code_if_IsPublic_is_true_with_no_credentials_and_ClientSecretBasic()
    {
        var validator = MakeValidator();
        var client = new ClientRegistration
        {
            ClientId = "client",
            Credentials = [],
            IsPublic = true,
            RedirectUris = new HashSet<string>(["https://app.example.com/cb"], StringComparer.Ordinal),
            PostLogoutRedirectUris = new HashSet<string>(StringComparer.Ordinal),
            AllowedTokenEndpointAuthMethods = new HashSet<string>(
                [TokenEndpointAuthMethods.ClientSecretBasic], StringComparer.Ordinal)
        };

        var act = () => validator.Validate(client);

        act.Should().Throw<ZeeKayDaConfigurationException>()
            .Which.AggregatedFailures.Should().Contain(f => f.Code == "client.is_public.trinity_violation");
    }

    [Fact]
    public void Validate_fails_with_empty_and_trinity_codes_if_IsPublic_is_false_with_no_credentials_and_empty_auth_methods()
    {
        var validator = MakeValidator();
        var client = new ClientRegistration
        {
            ClientId = "client",
            Credentials = [],
            IsPublic = false,
            RedirectUris = new HashSet<string>(["https://app.example.com/cb"], StringComparer.Ordinal),
            PostLogoutRedirectUris = new HashSet<string>(StringComparer.Ordinal),
            AllowedTokenEndpointAuthMethods = new HashSet<string>(StringComparer.Ordinal)
        };

        var act = () => validator.Validate(client);

        var ex = act.Should().Throw<ZeeKayDaConfigurationException>().Which;
        ex.AggregatedFailures.Should().Contain(f => f.Code == "client.token_endpoint_auth_methods.empty");
        ex.AggregatedFailures.Should().Contain(f => f.Code == "client.is_public.trinity_violation");
    }

    [Fact]
    public void Validate_accepts_exactly_32_redirect_uris()
    {
        // The documented cap is inclusive: rejection starts strictly above 32, not at it.
        var validator = MakeValidator();
        var uris = Enumerable.Range(1, 32).Select(i => $"https://app.example.com/cb{i}");
        var client = MakeValidConfidentialClient() with
        {
            RedirectUris = new HashSet<string>(uris, StringComparer.Ordinal),
        };

        var act = () => validator.Validate(client);

        act.Should().NotThrow();
    }

    [Fact]
    public void Validate_reports_an_untrimmed_auth_method_entry_as_invalid_and_nothing_else()
    {
        // An invalid entry is reported once, as invalid — it must not additionally trip the
        // duplicate or unsupported-method checks it was never eligible for.
        var validator = MakeValidator();
        var client = new ClientRegistration
        {
            ClientId = "client",
            Credentials = [new FakeSecret()],
            IsPublic = false,
            RedirectUris = new HashSet<string>(["https://app.example.com/cb"], StringComparer.Ordinal),
            PostLogoutRedirectUris = new HashSet<string>(StringComparer.Ordinal),
            AllowedTokenEndpointAuthMethods = new HashSet<string>(
                [" client_secret_basic "], StringComparer.Ordinal)
        };

        var act = () => validator.Validate(client);

        var ex = act.Should().Throw<ZeeKayDaConfigurationException>().Which;
        ex.AggregatedFailures.Should().ContainSingle(
            f => f.Code.StartsWith("client.token_endpoint_auth_methods.", StringComparison.Ordinal))
            .Which.Code.Should().Be("client.token_endpoint_auth_methods.invalid_entry");
    }

    [Fact]
    public void Validate_reports_an_auth_method_entry_with_a_control_character_as_invalid()
    {
        var validator = MakeValidator();
        var client = new ClientRegistration
        {
            ClientId = "client",
            Credentials = [new FakeSecret()],
            IsPublic = false,
            RedirectUris = new HashSet<string>(["https://app.example.com/cb"], StringComparer.Ordinal),
            PostLogoutRedirectUris = new HashSet<string>(StringComparer.Ordinal),
            AllowedTokenEndpointAuthMethods = new HashSet<string>(
                ["client\u0001secret", TokenEndpointAuthMethods.ClientSecretBasic], StringComparer.Ordinal)
        };

        var act = () => validator.Validate(client);

        act.Should().Throw<ZeeKayDaConfigurationException>()
            .Which.AggregatedFailures.Should().Contain(
                f => f.Code == "client.token_endpoint_auth_methods.invalid_entry");
    }

    [Fact]
    public void Validate_fails_with_none_on_confidential_code_for_confidential_client_with_none_auth_method()
    {
        // A confidential client with {"none","client_secret_basic"} passes the trinity check
        // (it has credentials and is not "none-only") but advertising 'none' means it could be
        // called without credentials. RFC 6749 §2.3 reserves 'none' for public clients.
        var validator = MakeValidator();
        var client = new ClientRegistration
        {
            ClientId = "client",
            Credentials = [new FakeSecret()],
            IsPublic = false,
            RedirectUris = new HashSet<string>(["https://app.example.com/cb"], StringComparer.Ordinal),
            PostLogoutRedirectUris = new HashSet<string>(StringComparer.Ordinal),
            AllowedTokenEndpointAuthMethods = new HashSet<string>(
                [TokenEndpointAuthMethods.None, TokenEndpointAuthMethods.ClientSecretBasic],
                StringComparer.Ordinal)
        };

        var act = () => validator.Validate(client);

        act.Should().Throw<ZeeKayDaConfigurationException>()
            .Which.AggregatedFailures.Should().Contain(
                f => f.Code == "client.token_endpoint_auth_methods.none_on_confidential");
    }

    // ── Two-credential cap ────────────────────────────────────────────────────────────────────────

    [Fact]
    public void Validate_passes_for_client_with_two_secrets()
    {
        var validator = MakeValidator();

        // We need a confidential client with exactly 2 IClientSecret credentials.
        // Use object initialiser to bypass CreateConfidential (which only allows one credential).
        var client = new ClientRegistration
        {
            ClientId = "client",
            Credentials = [new FakeSecret(), new FakeSecret()],
            IsPublic = false,
            RedirectUris = new HashSet<string>(["https://app.example.com/cb"], StringComparer.Ordinal),
            PostLogoutRedirectUris = new HashSet<string>(StringComparer.Ordinal),
            AllowedTokenEndpointAuthMethods = new HashSet<string>(
                [TokenEndpointAuthMethods.ClientSecretBasic], StringComparer.Ordinal)
        };

        var act = () => validator.Validate(client);

        act.Should().NotThrow();
    }

    [Fact]
    public void Validate_fails_with_too_many_secrets_code_for_client_with_three_secrets()
    {
        var validator = MakeValidator();
        var client = new ClientRegistration
        {
            ClientId = "client",
            Credentials = [new FakeSecret(), new FakeSecret(), new FakeSecret()],
            IsPublic = false,
            RedirectUris = new HashSet<string>(["https://app.example.com/cb"], StringComparer.Ordinal),
            PostLogoutRedirectUris = new HashSet<string>(StringComparer.Ordinal),
            AllowedTokenEndpointAuthMethods = new HashSet<string>(
                [TokenEndpointAuthMethods.ClientSecretBasic], StringComparer.Ordinal)
        };

        var act = () => validator.Validate(client);

        act.Should().Throw<ZeeKayDaConfigurationException>()
            .Which.AggregatedFailures.Should().Contain(f => f.Code == "client.credentials.too_many_secrets");
    }

    // ── Empty-secret probe ────────────────────────────────────────────────────────────────────────

    [Fact]
    public void Validate_fails_with_empty_secret_accepted_code_if_credential_accepts_empty_secret()
    {
        // A hasher that accepts any presented value including empty
        var emptyAcceptingHasher = new FakeHasher(verifyResult: true);
        var validator = MakeValidator(hasher: emptyAcceptingHasher);

        var client = MakeValidConfidentialClient(secret: new FakeSecret());

        var act = () => validator.Validate(client);

        act.Should().Throw<ZeeKayDaConfigurationException>()
            .Which.AggregatedFailures.Should().Contain(f => f.Code == "client.credentials.empty_secret_accepted");
    }

    [Fact]
    public void Validate_fails_with_no_hasher_code_if_credential_has_no_matching_hasher()
    {
        // The validator's composite only has a FakeHasher (handles FakeSecret). A credential of type
        // AnySecret is handled by no registered hasher, so it can never be verified — it must be
        // rejected at registration rather than failing silently at runtime as invalid_client.
        var validator = MakeValidator(hasher: new FakeHasher());

        var client = new ClientRegistration
        {
            ClientId = "client",
            Credentials = [new AnySecret()],
            IsPublic = false,
            RedirectUris = new HashSet<string>(["https://app.example.com/cb"], StringComparer.Ordinal),
            PostLogoutRedirectUris = new HashSet<string>(StringComparer.Ordinal),
            AllowedTokenEndpointAuthMethods = new HashSet<string>(
                [TokenEndpointAuthMethods.ClientSecretBasic], StringComparer.Ordinal)
        };

        var act = () => validator.Validate(client);

        act.Should().Throw<ZeeKayDaConfigurationException>()
            .Which.AggregatedFailures.Should().Contain(f => f.Code == "client.credentials.no_hasher");
    }

    // ── AllowedSigningAlgorithms ──────────────────────────────────────────────────────────────────

    [Fact]
    public void Validate_passes_if_AllowedSigningAlgorithms_is_null()
    {
        var validator = MakeValidator();
        var client = MakeValidPublicClient() with { AllowedSigningAlgorithms = null };

        var act = () => validator.Validate(client);

        act.Should().NotThrow();
    }

    [Fact]
    public void Validate_fails_with_empty_when_set_code_if_AllowedSigningAlgorithms_is_empty()
    {
        var validator = MakeValidator();
        var client = MakeValidPublicClient() with
        {
            AllowedSigningAlgorithms = new HashSet<SigningAlgorithm>()
        };

        var act = () => validator.Validate(client);

        act.Should().Throw<ZeeKayDaConfigurationException>()
            .Which.AggregatedFailures.Should().Contain(f => f.Code == "client.signing_algorithms.empty_when_set");
    }

    [Fact]
    public void Validate_passes_if_AllowedSigningAlgorithms_is_subset_of_server_algorithms()
    {
        var opts = new AuthorizationServerOptions { Issuer = "https://test.example.com" };
        // Include None so public clients (AllowedTokenEndpointAuthMethods={"none"}) pass subset check.
        opts.TokenEndpoint.AuthMethodsSupported.Add(TokenEndpointAuthMethods.None);
        var validator = MakeValidator(
            serverOptions: opts,
            keySet: TestSigningKeys.KeySet(SigningAlgorithm.RS256, SigningAlgorithm.ES256));

        var client = MakeValidPublicClient() with
        {
            AllowedSigningAlgorithms = new HashSet<SigningAlgorithm> { SigningAlgorithm.RS256 }
        };

        var act = () => validator.Validate(client);

        act.Should().NotThrow();
    }

    [Fact]
    public void Validate_fails_with_not_subset_code_if_AllowedSigningAlgorithms_is_not_subset_of_server_algorithms()
    {
        var opts = new AuthorizationServerOptions { Issuer = "https://test.example.com" };
        opts.TokenEndpoint.AuthMethodsSupported.Add(TokenEndpointAuthMethods.None);
        var validator = MakeValidator(
            serverOptions: opts, keySet: TestSigningKeys.KeySet(SigningAlgorithm.RS256));

        var client = MakeValidPublicClient() with
        {
            AllowedSigningAlgorithms = new HashSet<SigningAlgorithm> { SigningAlgorithm.ES512 }
        };

        var act = () => validator.Validate(client);

        act.Should().Throw<ZeeKayDaConfigurationException>()
            .Which.AggregatedFailures.Should().Contain(f => f.Code == "client.signing_algorithms.not_subset");
    }

    [Fact]
    public void Validate_fails_if_AllowedSigningAlgorithms_entry_is_withheld_by_the_advertised_filter()
    {
        var opts = new AuthorizationServerOptions { Issuer = "https://test.example.com" };
        opts.IdToken.AdvertisedSigningAlgorithms = [SigningAlgorithm.RS256];
        opts.TokenEndpoint.AuthMethodsSupported.Add(TokenEndpointAuthMethods.None);
        var validator = MakeValidator(
            serverOptions: opts,
            keySet: TestSigningKeys.KeySet(SigningAlgorithm.RS256, SigningAlgorithm.ES256));

        var client = MakeValidPublicClient() with
        {
            AllowedSigningAlgorithms = new HashSet<SigningAlgorithm> { SigningAlgorithm.ES256 }
        };

        var act = () => validator.Validate(client);

        act.Should().Throw<ZeeKayDaConfigurationException>()
            .Which.AggregatedFailures.Should().Contain(f => f.Code == "client.signing_algorithms.not_subset",
                "the server holds an ES256 key but the operator has withheld it from discovery");
    }

    [Fact]
    public void Validate_checks_against_the_filter_alone_when_the_key_ring_has_not_read_its_source()
    {
        var opts = new AuthorizationServerOptions { Issuer = "https://test.example.com" };
        opts.IdToken.AdvertisedSigningAlgorithms = [SigningAlgorithm.RS256];
        opts.TokenEndpoint.AuthMethodsSupported.Add(TokenEndpointAuthMethods.None);
        var validator = MakeValidator(serverOptions: opts, keySet: null);

        var client = MakeValidPublicClient() with
        {
            AllowedSigningAlgorithms = new HashSet<SigningAlgorithm> { SigningAlgorithm.ES512 }
        };

        var act = () => validator.Validate(client);

        act.Should().Throw<ZeeKayDaConfigurationException>()
            .Which.AggregatedFailures.Should().Contain(f => f.Code == "client.signing_algorithms.not_subset");
    }

    [Fact]
    public void Validate_warns_when_the_key_ring_exists_but_has_not_read_its_source()
    {
        // A host that resolves IClientRepository before startup verification runs gets no subset
        // check at all. That window is unchecked by anything else, so it is logged rather than
        // passed over in silence.
        var opts = new AuthorizationServerOptions { Issuer = "https://test.example.com" };
        opts.TokenEndpoint.AuthMethodsSupported.Add(TokenEndpointAuthMethods.None);
        var logger = new CapturingLogger();
        var validator = MakeValidator(logger: logger, serverOptions: opts, keySet: null);

        var client = MakeValidPublicClient() with
        {
            AllowedSigningAlgorithms = new HashSet<SigningAlgorithm> { SigningAlgorithm.ES512 }
        };

        validator.Validate(client);

        logger.Warnings.Should().ContainSingle(w => w.Contains("has not yet read its source"));
    }

    [Fact]
    public void Validate_skips_the_subset_check_when_there_is_no_key_set_and_no_filter()
    {
        var opts = new AuthorizationServerOptions { Issuer = "https://test.example.com" };
        opts.TokenEndpoint.AuthMethodsSupported.Add(TokenEndpointAuthMethods.None);
        var validator = MakeValidator(serverOptions: opts, withKeyRing: false);

        var client = MakeValidPublicClient() with
        {
            AllowedSigningAlgorithms = new HashSet<SigningAlgorithm> { SigningAlgorithm.ES512 }
        };

        var act = () => validator.Validate(client);

        act.Should().NotThrow("there is nothing yet for the client's set to be a subset of");
    }

    // ── AllowedScopes ─────────────────────────────────────────────────────────────────────────────

    [Fact]
    public void Validate_fails_with_blank_entry_code_if_AllowedScopes_contains_blank_entry()
    {
        var validator = MakeValidator();
        var client = MakeValidPublicClient() with
        {
            AllowedScopes = new HashSet<string>(["openid", ""], StringComparer.Ordinal)
        };

        var act = () => validator.Validate(client);

        act.Should().Throw<ZeeKayDaConfigurationException>()
            .Which.AggregatedFailures.Should().Contain(f => f.Code == "client.allowed_scopes.blank_entry");
    }

    [Fact]
    public void Validate_fails_with_blank_entry_code_if_AllowedScopes_contains_whitespace_entry()
    {
        var validator = MakeValidator();
        var client = MakeValidPublicClient() with
        {
            AllowedScopes = new HashSet<string>(["openid", "  "], StringComparer.Ordinal)
        };

        var act = () => validator.Validate(client);

        act.Should().Throw<ZeeKayDaConfigurationException>()
            .Which.AggregatedFailures.Should().Contain(f => f.Code == "client.allowed_scopes.blank_entry");
    }

    // ── AllowedTokenEndpointAuthMethods ──────────────────────────────────────────────────────────

    [Fact]
    public void Validate_fails_with_not_subset_code_if_auth_method_is_not_in_server_subset()
    {
        // Default server supports only ClientSecretBasic
        var validator = MakeValidator();
        var client = new ClientRegistration
        {
            ClientId = "client",
            Credentials = [new FakeSecret()],
            IsPublic = false,
            RedirectUris = new HashSet<string>(["https://app.example.com/cb"], StringComparer.Ordinal),
            PostLogoutRedirectUris = new HashSet<string>(StringComparer.Ordinal),
            AllowedTokenEndpointAuthMethods = new HashSet<string>(
                ["private_key_jwt"], StringComparer.Ordinal)
        };

        var act = () => validator.Validate(client);

        act.Should().Throw<ZeeKayDaConfigurationException>()
            .Which.AggregatedFailures.Should().Contain(f => f.Code == "client.token_endpoint_auth_methods.not_subset");
    }

    // ── Enum.IsDefined checks ─────────────────────────────────────────────────────────────────────

    [Fact]
    public void Validate_fails_with_grant_type_undefined_value_code_for_undefined_GrantType()
    {
        var validator = MakeValidator();
        var client = MakeValidPublicClient() with
        {
            AllowedGrantTypes = new HashSet<GrantType> { (GrantType)999 }
        };

        var act = () => validator.Validate(client);

        act.Should().Throw<ZeeKayDaConfigurationException>()
            .Which.AggregatedFailures.Should().Contain(f => f.Code == "client.grant_types.undefined_value");
    }

    [Fact]
    public void Validate_fails_with_response_type_undefined_value_code_for_undefined_ResponseType()
    {
        var validator = MakeValidator();
        var client = MakeValidPublicClient() with
        {
            AllowedResponseTypes = new HashSet<ResponseType> { (ResponseType)999 }
        };

        var act = () => validator.Validate(client);

        act.Should().Throw<ZeeKayDaConfigurationException>()
            .Which.AggregatedFailures.Should().Contain(f => f.Code == "client.response_types.undefined_value");
    }

    [Fact]
    public void Validate_fails_with_response_mode_undefined_value_code_for_undefined_ResponseMode()
    {
        var validator = MakeValidator();
        var client = MakeValidPublicClient() with
        {
            AllowedResponseModes = new HashSet<ResponseMode> { (ResponseMode)999 }
        };

        var act = () => validator.Validate(client);

        act.Should().Throw<ZeeKayDaConfigurationException>()
            .Which.AggregatedFailures.Should().Contain(f => f.Code == "client.response_modes.undefined_value");
    }

    [Fact]
    public void Validate_fails_with_prompt_value_undefined_value_code_for_undefined_PromptValue()
    {
        var validator = MakeValidator();
        var client = MakeValidPublicClient() with
        {
            AllowedPromptValues = new HashSet<PromptValue> { (PromptValue)999 }
        };

        var act = () => validator.Validate(client);

        act.Should().Throw<ZeeKayDaConfigurationException>()
            .Which.AggregatedFailures.Should().Contain(f => f.Code == "client.prompt_values.undefined_value");
    }

    // ── ClientId format ───────────────────────────────────────────────────────────────────────────

    [Fact]
    public void Validate_fails_with_client_id_invalid_code_if_ClientId_contains_invalid_characters()
    {
        var validator = MakeValidator();
        var client = MakeValidPublicClient() with { ClientId = "my client!" };

        var act = () => validator.Validate(client);

        act.Should().Throw<ZeeKayDaConfigurationException>()
            .Which.AggregatedFailures.Should().Contain(f => f.Code == "client.client_id.invalid");
    }

    [Theory]
    [InlineData("   ")]
    [InlineData(" x")]
    [InlineData("Example\tApp")]
    [InlineData("Example\nApp")]
    public void Validate_fails_with_display_name_invalid_code_for_a_blank_or_unprintable_DisplayName(string displayName)
    {
        // The name is rendered by the host's pages; a registration is the wrong place to carry
        // something a page would have to defend itself against.
        var validator = MakeValidator();
        var client = MakeValidPublicClient() with { DisplayName = displayName };

        var act = () => validator.Validate(client);

        act.Should().Throw<ZeeKayDaConfigurationException>()
            .Which.AggregatedFailures.Should().Contain(f => f.Code == "client.display_name.invalid");
    }

    [Fact]
    public void Validate_fails_with_display_name_invalid_code_if_DisplayName_is_too_long()
    {
        var validator = MakeValidator();
        var client = MakeValidPublicClient() with { DisplayName = new string('a', 201) };

        var act = () => validator.Validate(client);

        act.Should().Throw<ZeeKayDaConfigurationException>()
            .Which.AggregatedFailures.Should().Contain(f => f.Code == "client.display_name.invalid");
    }

    [Theory]
    [InlineData(null)]
    [InlineData("Example App")]
    [InlineData("Ångström & Söhne — 顧客ポータル")]
    public void Validate_accepts_an_absent_or_printable_DisplayName(string? displayName)
    {
        var validator = MakeValidator();
        var client = MakeValidPublicClient() with { DisplayName = displayName };

        var act = () => validator.Validate(client);

        act.Should().NotThrow();
    }

    [Fact]
    public void Validate_fails_with_client_id_invalid_code_if_ClientId_is_too_long()
    {
        var validator = MakeValidator();
        var client = MakeValidPublicClient() with { ClientId = new string('a', 201) };

        var act = () => validator.Validate(client);

        act.Should().Throw<ZeeKayDaConfigurationException>()
            .Which.AggregatedFailures.Should().Contain(f => f.Code == "client.client_id.invalid");
    }

    // ── Aggregate failures ────────────────────────────────────────────────────────────────────────

    [Fact]
    public void Validate_aggregates_all_failures_for_multiple_violations()
    {
        var validator = MakeValidator();
        var client = new ClientRegistration
        {
            ClientId = "my client!", // invalid client_id
            Credentials = [],
            IsPublic = false, // trinity violation: IsPublic=false, no credentials, auth methods empty
            RedirectUris = new HashSet<string>(
                ["https://app.example.com/cb#frag"], StringComparer.Ordinal), // fragment
            PostLogoutRedirectUris = new HashSet<string>(StringComparer.Ordinal),
            AllowedTokenEndpointAuthMethods = new HashSet<string>(StringComparer.Ordinal)
        };

        var act = () => validator.Validate(client);

        act.Should().Throw<ZeeKayDaConfigurationException>()
            .Which.AggregatedFailures.Count.Should().BeGreaterThan(1);
    }

    // ── Argument validation ───────────────────────────────────────────────────────────────────────

    [Fact]
    public void Validate_throws_ArgumentNullException_if_client_is_null()
    {
        var validator = MakeValidator();

        var act = () => validator.Validate(null!);

        act.Should().Throw<ArgumentNullException>();
    }

    // ── Redirect URI — unparseable string ────────────────────────────────────────────────────────

    [Fact]
    public void Validate_fails_with_invalid_code_if_redirect_uri_string_is_not_a_valid_URI()
    {
        var validator = MakeValidator();
        var client = MakeValidPublicClient() with
        {
            RedirectUris = new HashSet<string>(["not a uri"], StringComparer.Ordinal)
        };

        var act = () => validator.Validate(client);

        act.Should().Throw<ZeeKayDaConfigurationException>()
            .Which.AggregatedFailures.Should().Contain(f => f.Code == "client.redirect_uri.invalid");
    }

    // ── Redirect URI — IPv6 loopback with brackets ────────────────────────────────────────────────

    [Fact]
    public void Validate_passes_for_HTTP_IPv6_loopback_in_bracket_form()
    {
        var validator = MakeValidator();
        var client = MakeValidPublicClient() with
        {
            RedirectUris = new HashSet<string>(["http://[::1]/callback"], StringComparer.Ordinal)
        };

        var act = () => validator.Validate(client);

        act.Should().NotThrow();
    }

    // ── ClientId — null ───────────────────────────────────────────────────────────────────────────

    [Fact]
    public void Validate_fails_with_client_id_invalid_code_if_ClientId_is_null()
    {
        var validator = MakeValidator();
        var client = MakeValidPublicClient() with { ClientId = null! };

        var act = () => validator.Validate(client);

        act.Should().Throw<ZeeKayDaConfigurationException>()
            .Which.AggregatedFailures.Should().Contain(f => f.Code == "client.client_id.invalid");
    }

    // ── AllowedTokenEndpointAuthMethods — invalid entries ────────────────────────────────────────

    [Fact]
    public void Validate_fails_with_invalid_entry_code_if_auth_method_has_leading_whitespace()
    {
        var validator = MakeValidator();
        var client = new ClientRegistration
        {
            ClientId = "client",
            Credentials = [new FakeSecret()],
            IsPublic = false,
            RedirectUris = new HashSet<string>(["https://app.example.com/cb"], StringComparer.Ordinal),
            PostLogoutRedirectUris = new HashSet<string>(StringComparer.Ordinal),
            AllowedTokenEndpointAuthMethods = new HashSet<string>(
                [" client_secret_basic"], StringComparer.Ordinal)
        };

        var act = () => validator.Validate(client);

        act.Should().Throw<ZeeKayDaConfigurationException>()
            .Which.AggregatedFailures.Should().Contain(
                f => f.Code == "client.token_endpoint_auth_methods.invalid_entry");
    }

    [Fact]
    public void Validate_fails_with_invalid_entry_code_if_auth_method_has_control_character()
    {
        var validator = MakeValidator();
        var client = new ClientRegistration
        {
            ClientId = "client",
            Credentials = [new FakeSecret()],
            IsPublic = false,
            RedirectUris = new HashSet<string>(["https://app.example.com/cb"], StringComparer.Ordinal),
            PostLogoutRedirectUris = new HashSet<string>(StringComparer.Ordinal),
            AllowedTokenEndpointAuthMethods = new HashSet<string>(
                ["client\x01secret"], StringComparer.Ordinal)
        };

        var act = () => validator.Validate(client);

        act.Should().Throw<ZeeKayDaConfigurationException>()
            .Which.AggregatedFailures.Should().Contain(
                f => f.Code == "client.token_endpoint_auth_methods.invalid_entry");
    }

    // ── AllowedTokenEndpointAuthMethods — duplicate ───────────────────────────────────────────────

    [Fact]
    public void Validate_fails_with_duplicate_code_for_duplicate_auth_method()
    {
        // IReadOnlySet<string> deduplicates, so we use a custom stub that allows duplicate entries.
        var validator = MakeValidator();
        var client = new ClientRegistration
        {
            ClientId = "client",
            Credentials = [new FakeSecret()],
            IsPublic = false,
            RedirectUris = new HashSet<string>(["https://app.example.com/cb"], StringComparer.Ordinal),
            PostLogoutRedirectUris = new HashSet<string>(StringComparer.Ordinal),
            AllowedTokenEndpointAuthMethods = new DuplicatingSet(
                TokenEndpointAuthMethods.ClientSecretBasic,
                TokenEndpointAuthMethods.ClientSecretBasic)
        };

        var act = () => validator.Validate(client);

        act.Should().Throw<ZeeKayDaConfigurationException>()
            .Which.AggregatedFailures.Should().Contain(
                f => f.Code == "client.token_endpoint_auth_methods.duplicate");
    }

    // ── AllowedTokenEndpointAuthMethods — ToWireFormat arms ──────────────────────────────────────

    [Fact]
    public void Validate_failure_message_contains_wire_string_if_ClientSecretJwt_is_not_in_server_subset()
    {
        var validator = MakeValidator(); // default server: client_secret_basic + none
        var client = new ClientRegistration
        {
            ClientId = "client",
            Credentials = [new FakeSecret()],
            IsPublic = false,
            RedirectUris = new HashSet<string>(["https://app.example.com/cb"], StringComparer.Ordinal),
            PostLogoutRedirectUris = new HashSet<string>(StringComparer.Ordinal),
            AllowedTokenEndpointAuthMethods = new HashSet<string>(
                ["client_secret_jwt"], StringComparer.Ordinal)
        };

        var act = () => validator.Validate(client);

        act.Should().Throw<ZeeKayDaConfigurationException>()
            .Which.AggregatedFailures.Should().Contain(f =>
                f.Code == "client.token_endpoint_auth_methods.not_subset" &&
                f.Message.Contains("client_secret_jwt"));
    }

    [Fact]
    public void Validate_failure_message_contains_wire_string_if_ClientSecretPost_is_not_in_server_subset()
    {
        // Explicitly configure a server that only supports client_secret_basic so that a client
        // registering client_secret_post fails the subset check.
        var serverOptions = new AuthorizationServerOptions { Issuer = "https://test.example.com" };
        serverOptions.TokenEndpoint.AuthMethodsSupported =
            [TokenEndpointAuthMethods.ClientSecretBasic, TokenEndpointAuthMethods.None];
        var validator = MakeValidator(serverOptions: serverOptions);
        var client = new ClientRegistration
        {
            ClientId = "client",
            Credentials = [new FakeSecret()],
            IsPublic = false,
            RedirectUris = new HashSet<string>(["https://app.example.com/cb"], StringComparer.Ordinal),
            PostLogoutRedirectUris = new HashSet<string>(StringComparer.Ordinal),
            AllowedTokenEndpointAuthMethods = new HashSet<string>(
                ["client_secret_post"], StringComparer.Ordinal)
        };

        var act = () => validator.Validate(client);

        act.Should().Throw<ZeeKayDaConfigurationException>()
            .Which.AggregatedFailures.Should().Contain(f =>
                f.Code == "client.token_endpoint_auth_methods.not_subset" &&
                f.Message.Contains("client_secret_post"));
    }

    [Fact]
    public void Validate_failure_message_contains_wire_string_for_public_client_if_None_is_not_in_server_subset()
    {
        // Server has only client_secret_basic (no none) — public client's {"none"} fails subset.
        var opts = new AuthorizationServerOptions { Issuer = "https://test.example.com" };
        // Deliberately do NOT add TokenEndpointAuthMethods.None
        var validator = MakeValidator(serverOptions: opts);
        var client = ClientRegistration.CreatePublic(
            "client",
            ["https://app.example.com/cb"],
            [],
            ["openid"]);

        var act = () => validator.Validate(client);

        act.Should().Throw<ZeeKayDaConfigurationException>()
            .Which.AggregatedFailures.Should().Contain(f =>
                f.Code == "client.token_endpoint_auth_methods.not_subset" &&
                f.Message.Contains("none"));
    }

    // ── Credential registration constraints ──────────────────────────────────────────────────────

    /// <summary>
    /// A hasher that handles <see cref="FakeSecret"/> and returns a predictable failure from
    /// <see cref="IClientSecretHasher.GetRegistrationFailures"/>. Used to verify the validator
    /// delegates to the hasher rather than implementing its own type-specific checks.
    /// </summary>
    private sealed class RegistrationFailingHasher : IClientSecretHasher
    {
        public bool CanHandle(IClientSecret secret) => secret is FakeSecret;
        public bool Verify(IClientSecret stored, ReadOnlySpan<char> presented) => false;
        public IClientSecret Create(ReadOnlySpan<char> plaintext) => new FakeSecret();

        public IEnumerable<ZeeKayDaConfigurationFailure> GetRegistrationFailures(
            IClientSecret credential, string clientId)
        {
            yield return new ZeeKayDaConfigurationFailure(
                "test.fake_constraint",
                $"Client '{clientId}' failed fake constraint.");
        }
    }

    [Fact]
    public void Validate_aggregates_registration_failures_from_hasher_GetRegistrationFailures()
    {
        var validator = MakeValidator(new RegistrationFailingHasher());
        var client = MakeValidConfidentialClient();

        var act = () => validator.Validate(client);

        act.Should().Throw<ZeeKayDaConfigurationException>()
            .Which.AggregatedFailures.Should().ContainSingle(f =>
                f.Code == "test.fake_constraint" &&
                f.Message.Contains("test-client"));
    }

    // ── DuplicatingSet helper ─────────────────────────────────────────────────────────────────────

    /// <summary>
    /// A minimal <see cref="IReadOnlySet{T}"/> that enumerates duplicate entries, used to exercise
    /// the duplicate-detection branch in <c>ValidateAllowedTokenEndpointAuthMethods</c>. A real
    /// <see cref="HashSet{T}"/> would silently deduplicate and never trigger the check.
    /// </summary>
    private sealed class DuplicatingSet : IReadOnlySet<string>
    {
        private readonly List<string> _items;

        public DuplicatingSet(params string[] items) => _items = [.. items];

        public int Count => _items.Count;

        public bool Contains(string item) => _items.Contains(item, StringComparer.Ordinal);

        public IEnumerator<string> GetEnumerator() => _items.GetEnumerator();

        System.Collections.IEnumerator System.Collections.IEnumerable.GetEnumerator()
            => _items.GetEnumerator();

        public bool IsProperSubsetOf(IEnumerable<string> other) => throw new NotSupportedException();
        public bool IsProperSupersetOf(IEnumerable<string> other) => throw new NotSupportedException();
        public bool IsSubsetOf(IEnumerable<string> other) => throw new NotSupportedException();
        public bool IsSupersetOf(IEnumerable<string> other) => throw new NotSupportedException();
        public bool Overlaps(IEnumerable<string> other) => throw new NotSupportedException();
        public bool SetEquals(IEnumerable<string> other) => throw new NotSupportedException();
    }
}
