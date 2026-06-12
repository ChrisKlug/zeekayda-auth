using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using ZeeKayDa.Auth.Clients;
using ZeeKayDa.Auth.Configuration;

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

        public IClientSecret Create(string plaintext) => new FakeSecret();
    }

    /// <summary>A hasher that handles <see cref="AnySecret"/> and always returns false.</summary>
    private sealed class FallbackHasher : IClientSecretHasher
    {
        public bool CanHandle(IClientSecret secret) => secret is AnySecret;
        public bool Verify(IClientSecret stored, ReadOnlySpan<char> presented) => false;
        public IClientSecret Create(string plaintext) => new AnySecret();
    }

    /// <summary>
    /// A logger that records LogWarning calls for assertion.
    /// </summary>
    private sealed class CapturingLogger : ILogger<ClientRegistrationValidator>
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
        ILogger<ClientRegistrationValidator>? logger = null,
        AuthorizationServerOptions? serverOptions = null)
    {
        var opts = serverOptions ?? BuildDefaultServerOptions();

        var composite = MakeHasher(hasher ?? new FakeHasher());
        return new ClientRegistrationValidator(
            Options.Create(opts),
            composite,
            logger ?? NullLogger<ClientRegistrationValidator>.Instance);
    }

    private static AuthorizationServerOptions BuildDefaultServerOptions()
    {
        var opts = new AuthorizationServerOptions { Issuer = "https://test.example.com" };
        // Include "none" so public clients (AllowedTokenEndpointAuthMethods={"none"}) pass
        // the subset check. Confidential clients use "client_secret_basic" which is already default.
        opts.TokenEndpoint.AuthMethodsSupported.Add(TokenEndpointAuthMethod.None);
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
    public void Validate_ValidPublicClient_DoesNotThrow()
    {
        var validator = MakeValidator();
        var client = MakeValidPublicClient();

        var act = () => validator.Validate(client);

        act.Should().NotThrow();
    }

    [Fact]
    public void Validate_ValidConfidentialClient_DoesNotThrow()
    {
        var validator = MakeValidator();
        var client = MakeValidConfidentialClient();

        var act = () => validator.Validate(client);

        act.Should().NotThrow();
    }

    // ── Redirect URI rules ────────────────────────────────────────────────────────────────────────

    [Fact]
    public void Validate_HttpsRedirectUri_Passes()
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
    public void Validate_HttpLoopbackRedirectUri_Passes()
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
    public void Validate_HttpIpv6LoopbackRedirectUri_Passes()
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
    public void Validate_PrivateUseSchemeWithDot_Passes()
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
    public void Validate_UriWithFragment_FailsWithFragmentCode()
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
    public void Validate_UriWithUserInfo_FailsWithUserInfoCode()
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
    public void Validate_JavascriptScheme_FailsWithSchemeNotAllowedCode()
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
    public void Validate_HttpNonLoopback_FailsWithSchemeHttpNonLoopbackCode()
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
    public void Validate_LocalhostRedirectUri_EmitsLogWarning()
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
    public void Validate_LocalhostUriWithFragment_FailsWithFragmentCodeAndSuppressesLocalhostWarning()
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
    public void Validate_LocalhostAttackerSubdomain_FailsWithSchemeHttpNonLoopbackCode()
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
    public void Validate_HttpIpv6WithZoneId_FailsWithIpv6ZoneIdCode()
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
    public void Validate_HttpsIpv6WithZoneId_FailsWithIpv6ZoneIdCode()
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
    public void Validate_HttpsLocalhostRedirectUri_PassesButEmitsLogWarning()
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
    public void Validate_PercentEncodedUri_DoesNotNormalize()
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
    public void Validate_PathTraversal_FailsWithPathTraversalCode()
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
    public void Validate_PathTraversalWithQuerySuffix_FailsWithPathTraversalCode()
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
    public void Validate_PathTraversalWithMixedPercentEncoding_FailsWithPathTraversalCode()
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
    public void Validate_PrivateUseSingleSlashPathTraversal_FailsWithPathTraversalCode()
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
    public void Validate_QueryWithBracketedPercentEncoding_DoesNotFalseFlagZoneId()
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
    public void Validate_MoreThan32RedirectUris_FailsWithCountExceededCode()
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
    public void Validate_PostLogoutRedirectUriWithFragment_FailsWithFragmentCode()
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
    public void Validate_MoreThan32PostLogoutRedirectUris_FailsWithCountExceededCode()
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
    public void Validate_PublicClientWithNoCredentialsAndNoneMethod_Passes()
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
    public void Validate_ConfidentialClientWithSecretAndClientSecretBasic_Passes()
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
    public void Validate_IsPublicTrueWithCredential_FailsWithTrinityViolationCode()
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
    public void Validate_IsPublicFalseWithNoCredentialsAndClientSecretBasic_FailsWithTrinityViolationCode()
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
    public void Validate_IsPublicTrueWithNoCredentialsAndClientSecretBasic_FailsWithTrinityViolationCode()
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
    public void Validate_IsPublicFalseWithNoCredentialsAndEmptyAuthMethods_FailsWithEmptyAndTrinityCode()
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
    public void Validate_ConfidentialClientWithNoneInAuthMethods_FailsWithNoneOnConfidentialCode()
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
    public void Validate_TwoSecrets_Passes()
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
    public void Validate_ThreeSecrets_FailsWithTooManySecretsCode()
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
    public void Validate_CredentialAcceptsEmptySecret_FailsWithEmptySecretAcceptedCode()
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
    public void Validate_CredentialWithNoMatchingHasher_FailsWithNoHasherCode()
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
    public void Validate_AllowedSigningAlgorithmsNull_Passes()
    {
        var validator = MakeValidator();
        var client = MakeValidPublicClient() with { AllowedSigningAlgorithms = null };

        var act = () => validator.Validate(client);

        act.Should().NotThrow();
    }

    [Fact]
    public void Validate_AllowedSigningAlgorithmsEmptyWhenSet_FailsWithEmptyWhenSetCode()
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
    public void Validate_AllowedSigningAlgorithmsSubsetOfServer_Passes()
    {
        var opts = new AuthorizationServerOptions { Issuer = "https://test.example.com" };
        opts.IdToken.SigningAlgValuesSupported = [SigningAlgorithm.RS256, SigningAlgorithm.ES256];
        // Include None so public clients (AllowedTokenEndpointAuthMethods={"none"}) pass subset check.
        opts.TokenEndpoint.AuthMethodsSupported.Add(TokenEndpointAuthMethod.None);
        var validator = MakeValidator(serverOptions: opts);

        var client = MakeValidPublicClient() with
        {
            AllowedSigningAlgorithms = new HashSet<SigningAlgorithm> { SigningAlgorithm.RS256 }
        };

        var act = () => validator.Validate(client);

        act.Should().NotThrow();
    }

    [Fact]
    public void Validate_AllowedSigningAlgorithmsNotSubset_FailsWithNotSubsetCode()
    {
        var opts = new AuthorizationServerOptions { Issuer = "https://test.example.com" };
        opts.IdToken.SigningAlgValuesSupported = [SigningAlgorithm.RS256];
        opts.TokenEndpoint.AuthMethodsSupported.Add(TokenEndpointAuthMethod.None);
        var validator = MakeValidator(serverOptions: opts);

        var client = MakeValidPublicClient() with
        {
            AllowedSigningAlgorithms = new HashSet<SigningAlgorithm> { SigningAlgorithm.ES512 }
        };

        var act = () => validator.Validate(client);

        act.Should().Throw<ZeeKayDaConfigurationException>()
            .Which.AggregatedFailures.Should().Contain(f => f.Code == "client.signing_algorithms.not_subset");
    }

    // ── AllowedScopes ─────────────────────────────────────────────────────────────────────────────

    [Fact]
    public void Validate_AllowedScopesBlankEntry_FailsWithBlankEntryCode()
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
    public void Validate_AllowedScopesWhitespaceEntry_FailsWithBlankEntryCode()
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
    public void Validate_AuthMethodNotInServerSubset_FailsWithNotSubsetCode()
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
    public void Validate_UndefinedGrantType_FailsWithGrantTypeUndefinedValueCode()
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
    public void Validate_UndefinedResponseType_FailsWithResponseTypeUndefinedValueCode()
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
    public void Validate_UndefinedResponseMode_FailsWithResponseModeUndefinedValueCode()
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
    public void Validate_UndefinedPromptValue_FailsWithPromptValueUndefinedValueCode()
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
    public void Validate_ClientIdWithInvalidCharacters_FailsWithClientIdInvalidCode()
    {
        var validator = MakeValidator();
        var client = MakeValidPublicClient() with { ClientId = "my client!" };

        var act = () => validator.Validate(client);

        act.Should().Throw<ZeeKayDaConfigurationException>()
            .Which.AggregatedFailures.Should().Contain(f => f.Code == "client.client_id.invalid");
    }

    [Fact]
    public void Validate_ClientIdTooLong_FailsWithClientIdInvalidCode()
    {
        var validator = MakeValidator();
        var client = MakeValidPublicClient() with { ClientId = new string('a', 201) };

        var act = () => validator.Validate(client);

        act.Should().Throw<ZeeKayDaConfigurationException>()
            .Which.AggregatedFailures.Should().Contain(f => f.Code == "client.client_id.invalid");
    }

    // ── Aggregate failures ────────────────────────────────────────────────────────────────────────

    [Fact]
    public void Validate_MultipleViolations_AggregatesAllFailures()
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
    public void Validate_NullClient_ThrowsArgumentNullException()
    {
        var validator = MakeValidator();

        var act = () => validator.Validate(null!);

        act.Should().Throw<ArgumentNullException>();
    }

    // ── Redirect URI — unparseable string ────────────────────────────────────────────────────────

    [Fact]
    public void Validate_InvalidUriStringInRedirectUris_FailsWithInvalidCode()
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
    public void Validate_HttpIpv6LoopbackBracketForm_Passes()
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
    public void Validate_NullClientId_FailsWithClientIdInvalidCode()
    {
        var validator = MakeValidator();
        var client = MakeValidPublicClient() with { ClientId = null! };

        var act = () => validator.Validate(client);

        act.Should().Throw<ZeeKayDaConfigurationException>()
            .Which.AggregatedFailures.Should().Contain(f => f.Code == "client.client_id.invalid");
    }

    // ── AllowedTokenEndpointAuthMethods — invalid entries ────────────────────────────────────────

    [Fact]
    public void Validate_AuthMethodWithLeadingWhitespace_FailsWithInvalidEntryCode()
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
    public void Validate_AuthMethodWithControlCharacter_FailsWithInvalidEntryCode()
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
    public void Validate_DuplicateAuthMethod_FailsWithDuplicateCode()
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
    public void Validate_ClientSecretJwtNotInServerSubset_FailureMessageContainsWireString()
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
    public void Validate_ClientSecretPostNotInServerSubset_FailureMessageContainsWireString()
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
                ["client_secret_post"], StringComparer.Ordinal)
        };

        var act = () => validator.Validate(client);

        act.Should().Throw<ZeeKayDaConfigurationException>()
            .Which.AggregatedFailures.Should().Contain(f =>
                f.Code == "client.token_endpoint_auth_methods.not_subset" &&
                f.Message.Contains("client_secret_post"));
    }

    [Fact]
    public void Validate_NoneNotInServerSubset_PublicClient_FailureMessageContainsWireString()
    {
        // Server has only client_secret_basic (no none) — public client's {"none"} fails subset.
        var opts = new AuthorizationServerOptions { Issuer = "https://test.example.com" };
        // Deliberately do NOT add TokenEndpointAuthMethod.None
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
