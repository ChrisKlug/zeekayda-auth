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

    private static readonly ClientSecret FakeSecret = new("$fake$x");

    private static readonly ClientSecret AnySecret = new("$any$x");

    /// <summary>A hasher that owns the <c>fake</c> id and verifies nothing.</summary>
    private sealed class FakeHasher : IClientSecretHasher
    {
        public IReadOnlySet<string> AlgorithmIds { get; } = new HashSet<string> { "fake" };

        public bool Verify(ReadOnlySpan<char> presented, ClientSecret stored) => false;

        public ClientSecret Create(ReadOnlySpan<char> plaintext) => FakeSecret;
    }

    private static ClientSecretHasherRegistry MakeHasher(IClientSecretHasher hasher)
        => new ClientSecretHasherRegistry([hasher], Options.Create(new ClientSecretHasherRegistrationOptions()));

    private static ClientRegistrationValidator MakeValidator(
        IClientSecretHasher? hasher = null,
        SanitizingLogger<ClientRegistrationValidator>? logger = null,
        AuthorizationServerOptions? serverOptions = null,
        SigningKeySet? keySet = null,
        bool withKeyRing = true)
    {
        var opts = serverOptions ?? BuildDefaultServerOptions();

        var composite = MakeHasher(hasher ?? new FakeHasher());
        return new ClientRegistrationValidator(
            Options.Create(opts),
            TestAuthMethods.Advertised(opts),
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

        public Task<SigningOutcome> SignAsync<TState>(
            TState state,
            Func<SigningContext, TState, ReadOnlyMemory<byte>> buildSigningInput,
            CancellationToken cancellationToken = default)
            => throw new NotSupportedException();

        Task ISigningKeyRing.EnsureInitializedAsync(CancellationToken cancellationToken)
            => throw new NotSupportedException();

        SigningKeySet? ISigningKeyRing.CurrentOrNull => current;
    }

    /// <summary>
    /// A custom registration's set whose <c>Count</c> reports <paramref name="reportedCount"/>
    /// whatever it actually yields — the validator must count what it enumerates, not trust this.
    /// </summary>
    private sealed class MiscountingSet(IEnumerable<string> items, int reportedCount) : IReadOnlySet<string>
    {
        private readonly List<string> _items = [.. items];

        public int Count => reportedCount;
        public IEnumerator<string> GetEnumerator() => _items.GetEnumerator();
        System.Collections.IEnumerator System.Collections.IEnumerable.GetEnumerator() => GetEnumerator();
        public bool Contains(string item) => _items.Contains(item, StringComparer.Ordinal);
        public bool IsProperSubsetOf(IEnumerable<string> other) => throw new NotSupportedException();
        public bool IsProperSupersetOf(IEnumerable<string> other) => throw new NotSupportedException();
        public bool IsSubsetOf(IEnumerable<string> other) => throw new NotSupportedException();
        public bool IsSupersetOf(IEnumerable<string> other) => throw new NotSupportedException();
        public bool Overlaps(IEnumerable<string> other) => throw new NotSupportedException();
        public bool SetEquals(IEnumerable<string> other) => throw new NotSupportedException();
    }

    /// <summary>
    /// A custom registration's set that yields its items while reporting a <c>Count</c> of zero and
    /// denying that it contains any of them — the validator must go by what it enumerates.
    /// </summary>
    private sealed class MisreportingSet<T>(IEnumerable<T> items) : IReadOnlySet<T>
    {
        private readonly List<T> _items = [.. items];

        public int Count => 0;
        public IEnumerator<T> GetEnumerator() => _items.GetEnumerator();
        System.Collections.IEnumerator System.Collections.IEnumerable.GetEnumerator() => GetEnumerator();
        public bool Contains(T item) => false;
        public bool IsProperSubsetOf(IEnumerable<T> other) => throw new NotSupportedException();
        public bool IsProperSupersetOf(IEnumerable<T> other) => throw new NotSupportedException();
        public bool IsSubsetOf(IEnumerable<T> other) => throw new NotSupportedException();
        public bool IsSupersetOf(IEnumerable<T> other) => throw new NotSupportedException();
        public bool Overlaps(IEnumerable<T> other) => throw new NotSupportedException();
        public bool SetEquals(IEnumerable<T> other) => throw new NotSupportedException();
    }

    private static AuthorizationServerOptions BuildDefaultServerOptions()
    {
        return new AuthorizationServerOptions { Issuer = "https://test.example.com" };
    }

    private static Client MakeValidPublicClient(string clientId = "test-client") =>
        Client.CreatePublic(
            clientId,
            ["https://app.example.com/callback"],
            [],
            ["openid"]);

    private static Client MakeValidConfidentialClient(
        string clientId = "test-client",
        ClientSecret? secret = null) =>
        Client.CreateConfidential(
            clientId,
            secret ?? FakeSecret,
            ["https://app.example.com/callback"],
            [],
            ["openid"]);

    // ── Valid clients pass ────────────────────────────────────────────────────────────────────────

    [Fact]
    public void Validate_reports_no_failure_for_a_valid_public_client()
    {
        var validator = MakeValidator();
        var client = MakeValidPublicClient();

        var failures = validator.Validate(client);

        failures.Should().BeEmpty();
    }

    [Fact]
    public void A_custom_entity_implementing_only_its_id_credentials_redirect_URIs_and_scopes_is_a_valid_confidential_client()
    {
        var validator = MakeValidator();

        var failures = validator.Validate(new MinimalEntity());

        failures.Should().BeEmpty();
    }

    /// <summary>A store's own entity that leaves every other member to the interface default.</summary>
    private sealed class MinimalEntity : IClientWithCredentials
    {
        public string ClientId => "minimal";
        public IReadOnlyList<ClientSecret> Secrets { get; } = [FakeSecret];
        public IReadOnlySet<string> RedirectUris { get; } = new HashSet<string>(StringComparer.Ordinal) { "https://app.example.com/callback" };
        public IReadOnlySet<string> AllowedScopes { get; } = new HashSet<string>(StringComparer.Ordinal) { "openid" };
    }

    [Fact]
    public void Validate_reports_no_failure_for_a_valid_confidential_client()
    {
        var validator = MakeValidator();
        var client = MakeValidConfidentialClient();

        var failures = validator.Validate(client);

        failures.Should().BeEmpty();
    }

    // ── PKCE opt-out ──────────────────────────────────────────────────────────────────────────────

    [Fact]
    public void A_public_client_cannot_be_permitted_to_omit_pkce()
    {
        var validator = MakeValidator();
        var client = MakeValidPublicClient() with { RequirePkce = false };

        var failures = validator.Validate(client);

        failures.Should().Contain(f => f.Code == "client.require_pkce.disabled_on_public");
    }

    [Fact]
    public void A_confidential_client_may_be_permitted_to_omit_pkce()
    {
        var validator = MakeValidator();
        var client = MakeValidConfidentialClient() with { RequirePkce = false };

        var failures = validator.Validate(client);

        failures.Should().BeEmpty();
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

        var failures = validator.Validate(client);

        failures.Should().BeEmpty();
    }

    [Fact]
    public void Validate_passes_for_HTTP_loopback_redirect_uri()
    {
        var validator = MakeValidator();
        var client = MakeValidPublicClient() with
        {
            RedirectUris = new HashSet<string>(["http://127.0.0.1/callback"], StringComparer.Ordinal)
        };

        var failures = validator.Validate(client);

        failures.Should().BeEmpty();
    }

    [Fact]
    public void Validate_passes_for_HTTP_IPv6_loopback_redirect_uri()
    {
        var validator = MakeValidator();
        var client = MakeValidPublicClient() with
        {
            RedirectUris = new HashSet<string>(["http://[::1]/cb"], StringComparer.Ordinal)
        };

        var failures = validator.Validate(client);

        failures.Should().BeEmpty();
    }

    [Fact]
    public void Validate_passes_for_private_use_scheme_with_dot()
    {
        var validator = MakeValidator();
        var client = MakeValidPublicClient() with
        {
            RedirectUris = new HashSet<string>(["myapp.scheme://callback"], StringComparer.Ordinal)
        };

        var failures = validator.Validate(client);

        failures.Should().BeEmpty();
    }

    [Fact]
    public void Validate_fails_with_fragment_code_if_redirect_uri_has_fragment()
    {
        var validator = MakeValidator();
        var client = MakeValidPublicClient() with
        {
            RedirectUris = new HashSet<string>(["https://app.example.com/cb#x"], StringComparer.Ordinal)
        };

        var failures = validator.Validate(client);

        failures.Should().Contain(f => f.Code == "client.redirect_uri.fragment");
    }

    [Fact]
    public void Validate_fails_with_user_info_code_if_redirect_uri_has_user_info()
    {
        var validator = MakeValidator();
        var client = MakeValidPublicClient() with
        {
            RedirectUris = new HashSet<string>(["https://user@app.example.com/cb"], StringComparer.Ordinal)
        };

        var failures = validator.Validate(client);

        failures.Should().Contain(f => f.Code == "client.redirect_uri.userinfo");
    }

    [Fact]
    public void Validate_fails_with_scheme_not_allowed_code_if_redirect_uri_uses_javascript_scheme()
    {
        var validator = MakeValidator();
        var client = MakeValidPublicClient() with
        {
            RedirectUris = new HashSet<string>(["javascript:alert(1)"], StringComparer.Ordinal)
        };

        var failures = validator.Validate(client);

        failures.Should().Contain(f => f.Code == "client.redirect_uri.scheme_not_allowed");
    }

    [Fact]
    public void Validate_fails_with_scheme_http_non_loopback_code_if_redirect_uri_uses_HTTP_on_non_loopback()
    {
        var validator = MakeValidator();
        var client = MakeValidPublicClient() with
        {
            RedirectUris = new HashSet<string>(["http://attacker.com/cb"], StringComparer.Ordinal)
        };

        var failures = validator.Validate(client);

        failures.Should().Contain(f => f.Code == "client.redirect_uri.scheme_http_non_loopback");
    }

    [Fact]
    public void Validate_emits_log_warning_for_localhost_redirect_uri()
    {
        var logger = new CapturingSanitizingLogger<ClientRegistrationValidator>();
        var validator = MakeValidator(logger: logger);
        var client = MakeValidPublicClient() with
        {
            RedirectUris = new HashSet<string>(["http://localhost/callback"], StringComparer.Ordinal)
        };

        validator.Validate(client);

        logger.Warnings.Should().ContainSingle(w => w.Contains("localhost"));
    }

    // ── Advisories are written once ──────────────────────────────────────────────────────────────
    // The resolver validates on every lookup, so an advisory repeated per validation would let
    // anyone who knows a client_id write a Warning per request.

    [Fact]
    public void A_valid_registration_s_advisory_warning_is_written_once_not_per_lookup()
    {
        var logger = new CapturingSanitizingLogger<ClientRegistrationValidator>();
        var validator = MakeValidator(logger: logger);
        var client = MakeValidPublicClient() with
        {
            RedirectUris = new HashSet<string>(["http://localhost/callback"], StringComparer.Ordinal)
        };

        validator.Validate(client);
        validator.Validate(client);

        logger.Warnings.Should().ContainSingle(w => w.Contains("localhost"));
    }

    [Fact]
    public void A_second_localhost_redirect_uri_on_the_same_client_is_still_warned_about()
    {
        var logger = new CapturingSanitizingLogger<ClientRegistrationValidator>();
        var validator = MakeValidator(logger: logger);
        var client = MakeValidPublicClient() with
        {
            RedirectUris = new HashSet<string>(["http://localhost/callback"], StringComparer.Ordinal)
        };

        validator.Validate(client);
        validator.Validate(client with
        {
            RedirectUris = new HashSet<string>(["http://localhost/other"], StringComparer.Ordinal)
        });

        logger.Warnings.Should().HaveCount(2);
    }

    [Fact]
    public void The_same_localhost_redirect_uri_on_another_client_is_still_warned_about()
    {
        var logger = new CapturingSanitizingLogger<ClientRegistrationValidator>();
        var validator = MakeValidator(logger: logger);
        var redirectUris = new HashSet<string>(["http://localhost/callback"], StringComparer.Ordinal);

        validator.Validate(MakeValidPublicClient("client-a") with { RedirectUris = redirectUris });
        validator.Validate(MakeValidPublicClient("client-b") with { RedirectUris = redirectUris });

        logger.Warnings.Should().HaveCount(2);
    }

    [Fact]
    public void The_unread_key_ring_warning_is_written_once_per_client()
    {
        var logger = new CapturingSanitizingLogger<ClientRegistrationValidator>();
        var validator = MakeValidator(logger: logger, keySet: null);
        var client = MakeValidPublicClient() with
        {
            AllowedSigningAlgorithms = new HashSet<SigningAlgorithm> { SigningAlgorithm.ES512 }
        };

        validator.Validate(client);
        validator.Validate(client);

        logger.Warnings.Should().ContainSingle(w => w.Contains("has not yet read its source"));
    }

    [Fact]
    public void The_refresh_without_issuer_warning_is_written_once_per_client()
    {
        var options = BuildDefaultServerOptions();
        options.GrantTypesSupported.Add(GrantType.RefreshToken);
        var logger = new CapturingSanitizingLogger<ClientRegistrationValidator>();
        var validator = MakeValidator(logger: logger, serverOptions: options);
        var client = MakeValidPublicClient() with
        {
            AllowedGrantTypes = new HashSet<GrantType> { GrantType.RefreshToken },
            AllowedResponseTypes = new HashSet<ResponseType>(),
            AllowedResponseModes = new HashSet<ResponseMode>(),
        };

        validator.Validate(client);
        validator.Validate(client);

        logger.Warnings.Should().ContainSingle(w => w.Contains("refresh_token", StringComparison.Ordinal));
    }

    [Fact]
    public void The_lifetime_past_the_family_ceiling_warning_is_written_once_per_client_and_lifetime()
    {
        var opts = BuildDefaultServerOptions();
        opts.TokenEndpoint.AbsoluteFamilyLifetime = TimeSpan.FromDays(30);
        var logger = new CapturingSanitizingLogger<ClientRegistrationValidator>();
        var validator = MakeValidator(logger: logger, serverOptions: opts);
        var client = MakeValidPublicClient() with
        {
            AccessTokenLifetime = TimeSpan.FromDays(31),
            IdTokenLifetime = TimeSpan.FromDays(31),
        };

        validator.Validate(client);
        validator.Validate(client);

        logger.Warnings.Should().HaveCount(2)
            .And.Contain(w => w.Contains("AccessTokenLifetime"))
            .And.Contain(w => w.Contains("IdTokenLifetime"));
    }

    [Fact]
    public void Validate_fails_with_fragment_code_and_suppresses_localhost_warning_for_localhost_uri_with_fragment()
    {
        // The localhost advisory warning is noise when the URI is already being rejected for another
        // reason. A localhost URI carrying a fragment must produce the fragment failure but NOT the
        // localhost warning.
        var logger = new CapturingSanitizingLogger<ClientRegistrationValidator>();
        var validator = MakeValidator(logger: logger);
        var client = MakeValidPublicClient() with
        {
            RedirectUris = new HashSet<string>(["http://localhost/cb#frag"], StringComparer.Ordinal)
        };

        var failures = validator.Validate(client);

        failures.Should().Contain(f => f.Code == "client.redirect_uri.fragment");
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

        var failures = validator.Validate(client);

        failures.Should().Contain(f => f.Code == "client.redirect_uri.scheme_http_non_loopback");
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

        var failures = validator.Validate(client);

        failures.Should().Contain(f => f.Code == "client.redirect_uri.ipv6_zone_id");
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

        var failures = validator.Validate(client);

        failures.Should().Contain(f => f.Code == "client.redirect_uri.ipv6_zone_id");
    }

    [Fact]
    public void Validate_passes_without_log_warning_for_HTTPS_localhost_redirect_uri()
    {
        // The localhost advisory warning (RFC 8252 §8.3) is for native apps' http loopback
        // redirects. https://localhost is a web client on a dev certificate, where TLS already
        // rules out the name-resolution risk the advice is about.
        var logger = new CapturingSanitizingLogger<ClientRegistrationValidator>();
        var validator = MakeValidator(logger: logger);
        var client = MakeValidPublicClient() with
        {
            RedirectUris = new HashSet<string>(["https://localhost:5002/signin-oidc"], StringComparer.Ordinal)
        };

        var failures = validator.Validate(client);

        failures.Should().BeEmpty();
        logger.Warnings.Should().NotContain(w => w.Contains("localhost"));
    }

    [Fact]
    public void Validate_emits_log_warning_for_HTTP_localhost_post_logout_redirect_uri_but_not_HTTPS()
    {
        var logger = new CapturingSanitizingLogger<ClientRegistrationValidator>();
        var validator = MakeValidator(logger: logger);
        var client = MakeValidPublicClient() with
        {
            PostLogoutRedirectUris = new HashSet<string>(
                ["http://localhost/signed-out", "https://localhost:5002/signed-out"], StringComparer.Ordinal)
        };

        validator.Validate(client);

        logger.Warnings.Should().ContainSingle(w => w.Contains("localhost"))
            .Which.Should().Contain("http://localhost/signed-out");
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

        var failures = validator.Validate(client);

        failures.Should().BeEmpty();
    }

    [Fact]
    public void Validate_fails_with_path_traversal_code_if_redirect_uri_has_path_traversal()
    {
        var validator = MakeValidator();
        var client = MakeValidPublicClient() with
        {
            RedirectUris = new HashSet<string>(["https://app.example.com/../cb"], StringComparer.Ordinal)
        };

        var failures = validator.Validate(client);

        failures.Should().Contain(f => f.Code == "client.redirect_uri.path_traversal");
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

        var failures = validator.Validate(client);

        failures.Should().Contain(f => f.Code == "client.redirect_uri.path_traversal");
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

        var failures = validator.Validate(client);

        failures.Should().Contain(f => f.Code == "client.redirect_uri.path_traversal");
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

        var failures = validator.Validate(client);

        failures.Should().Contain(f => f.Code == "client.redirect_uri.path_traversal");
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

        var failures = validator.Validate(client);

        failures.Should().BeEmpty();
    }

    [Fact]
    public void Validate_fails_with_count_exceeded_code_if_more_than_32_redirect_uris()
    {
        var validator = MakeValidator();
        var uris = Enumerable.Range(1, 33)
            .Select(i => $"https://app.example.com/cb{i}")
            .ToHashSet(StringComparer.Ordinal);
        var client = MakeValidPublicClient() with { RedirectUris = uris };

        var failures = validator.Validate(client);

        failures.Should().Contain(f => f.Code == "client.redirect_uri.count_exceeded");
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

        var failures = validator.Validate(client);

        failures.Should().Contain(f => f.Code == "client.redirect_uri.fragment");
    }

    [Fact]
    public void Validate_fails_with_count_exceeded_code_if_redirect_uri_set_under_reports_its_count()
    {
        var validator = MakeValidator();
        var uris = Enumerable.Range(1, 33).Select(i => $"https://app.example.com/cb{i}");
        var client = MakeValidPublicClient() with
        {
            RedirectUris = new MiscountingSet(uris, reportedCount: 1)
        };

        var failures = validator.Validate(client);

        failures.Should().Contain(f => f.Code == "client.redirect_uri.count_exceeded");
    }

    [Fact]
    public void Validate_fails_with_count_exceeded_code_if_more_than_32_post_logout_redirect_uris()
    {
        var validator = MakeValidator();
        var uris = Enumerable.Range(1, 33)
            .Select(i => $"https://app.example.com/logout{i}")
            .ToHashSet(StringComparer.Ordinal);
        var client = MakeValidPublicClient() with { PostLogoutRedirectUris = uris };

        var failures = validator.Validate(client);

        failures.Should().Contain(f => f.Code == "client.redirect_uri.count_exceeded");
    }

    // ── IsPublic trinity ──────────────────────────────────────────────────────────────────────────

    [Fact]
    public void Validate_passes_for_public_client_with_no_credentials_and_none_auth_method()
    {
        var validator = MakeValidator();
        var client = Client.CreatePublic(
            "client",
            ["https://app.example.com/cb"],
            [],
            ["openid"]);

        var failures = validator.Validate(client);

        failures.Should().BeEmpty();
    }

    [Fact]
    public void Validate_passes_for_confidential_client_with_secret_and_ClientSecretBasic_auth_method()
    {
        var validator = MakeValidator();
        var client = Client.CreateConfidential(
            "client",
            FakeSecret,
            ["https://app.example.com/cb"],
            [],
            ["openid"]);

        var failures = validator.Validate(client);

        failures.Should().BeEmpty();
    }

    [Fact]
    public void Validate_fails_with_trinity_violation_code_if_auth_method_set_under_reports_its_count()
    {
        var validator = MakeValidator();
        var client = MakeValidPublicClient() with
        {
            AllowedTokenEndpointAuthMethods = new MiscountingSet(
                [TokenEndpointAuthMethods.None, TokenEndpointAuthMethods.ClientSecretBasic],
                reportedCount: 1)
        };

        var failures = validator.Validate(client);

        failures.Should().Contain(f => f.Code == "client.is_public.trinity_violation");
    }

    [Fact]
    public void Validate_fails_with_trinity_violation_code_if_IsPublic_is_true_but_has_credential()
    {
        var validator = MakeValidator();
        var client = new Client
        {
            ClientId = "client",
            Secrets = [FakeSecret],
            IsPublic = true,
            RedirectUris = new HashSet<string>(["https://app.example.com/cb"], StringComparer.Ordinal),
            PostLogoutRedirectUris = new HashSet<string>(StringComparer.Ordinal),
            AllowedTokenEndpointAuthMethods = new HashSet<string>(
                [TokenEndpointAuthMethods.None], StringComparer.Ordinal)
        };

        var failures = validator.Validate(client);

        failures.Should().Contain(f => f.Code == "client.is_public.trinity_violation");
    }

    [Fact]
    public void Validate_fails_with_trinity_violation_code_if_IsPublic_is_false_with_no_credentials_and_ClientSecretBasic()
    {
        var validator = MakeValidator();
        var client = new Client
        {
            ClientId = "client",
            Secrets = [],
            IsPublic = false,
            RedirectUris = new HashSet<string>(["https://app.example.com/cb"], StringComparer.Ordinal),
            PostLogoutRedirectUris = new HashSet<string>(StringComparer.Ordinal),
            AllowedTokenEndpointAuthMethods = new HashSet<string>(
                [TokenEndpointAuthMethods.ClientSecretBasic], StringComparer.Ordinal)
        };

        var failures = validator.Validate(client);

        failures.Should().Contain(f => f.Code == "client.is_public.trinity_violation");
    }

    [Fact]
    public void Validate_fails_with_trinity_violation_code_if_IsPublic_is_true_with_no_credentials_and_ClientSecretBasic()
    {
        var validator = MakeValidator();
        var client = new Client
        {
            ClientId = "client",
            Secrets = [],
            IsPublic = true,
            RedirectUris = new HashSet<string>(["https://app.example.com/cb"], StringComparer.Ordinal),
            PostLogoutRedirectUris = new HashSet<string>(StringComparer.Ordinal),
            AllowedTokenEndpointAuthMethods = new HashSet<string>(
                [TokenEndpointAuthMethods.ClientSecretBasic], StringComparer.Ordinal)
        };

        var failures = validator.Validate(client);

        failures.Should().Contain(f => f.Code == "client.is_public.trinity_violation");
    }

    [Fact]
    public void Validate_fails_with_empty_and_trinity_codes_if_IsPublic_is_false_with_no_credentials_and_empty_auth_methods()
    {
        var validator = MakeValidator();
        var client = new Client
        {
            ClientId = "client",
            Secrets = [],
            IsPublic = false,
            RedirectUris = new HashSet<string>(["https://app.example.com/cb"], StringComparer.Ordinal),
            PostLogoutRedirectUris = new HashSet<string>(StringComparer.Ordinal),
            AllowedTokenEndpointAuthMethods = new HashSet<string>(StringComparer.Ordinal)
        };

        var failures = validator.Validate(client);

        failures.Should().Contain(f => f.Code == "client.token_endpoint_auth_methods.empty");
        failures.Should().Contain(f => f.Code == "client.is_public.trinity_violation");
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

        var failures = validator.Validate(client);

        failures.Should().BeEmpty();
    }

    [Fact]
    public void Validate_reports_an_untrimmed_auth_method_entry_as_invalid_and_nothing_else()
    {
        // An invalid entry is reported once, as invalid — it must not additionally trip the
        // duplicate or unsupported-method checks it was never eligible for.
        var validator = MakeValidator();
        var client = new Client
        {
            ClientId = "client",
            Secrets = [FakeSecret],
            IsPublic = false,
            RedirectUris = new HashSet<string>(["https://app.example.com/cb"], StringComparer.Ordinal),
            PostLogoutRedirectUris = new HashSet<string>(StringComparer.Ordinal),
            AllowedTokenEndpointAuthMethods = new HashSet<string>(
                [" client_secret_basic "], StringComparer.Ordinal)
        };

        var failures = validator.Validate(client);

        failures.Should().ContainSingle(
    f => f.Code.StartsWith("client.token_endpoint_auth_methods.", StringComparison.Ordinal))
    .Which.Code.Should().Be("client.token_endpoint_auth_methods.invalid_entry");
    }

    [Fact]
    public void Validate_reports_an_auth_method_entry_with_a_control_character_as_invalid()
    {
        var validator = MakeValidator();
        var client = new Client
        {
            ClientId = "client",
            Secrets = [FakeSecret],
            IsPublic = false,
            RedirectUris = new HashSet<string>(["https://app.example.com/cb"], StringComparer.Ordinal),
            PostLogoutRedirectUris = new HashSet<string>(StringComparer.Ordinal),
            AllowedTokenEndpointAuthMethods = new HashSet<string>(
                ["client\u0001secret", TokenEndpointAuthMethods.ClientSecretBasic], StringComparer.Ordinal)
        };

        var failures = validator.Validate(client);

        failures.Should().Contain(
                f => f.Code == "client.token_endpoint_auth_methods.invalid_entry");
    }

    [Fact]
    public void Validate_fails_with_none_on_confidential_code_for_confidential_client_with_none_auth_method()
    {
        // A confidential client with {"none","client_secret_basic"} passes the trinity check
        // (it has credentials and is not "none-only") but advertising 'none' means it could be
        // called without credentials. RFC 6749 §2.3 reserves 'none' for public clients.
        var validator = MakeValidator();
        var client = new Client
        {
            ClientId = "client",
            Secrets = [FakeSecret],
            IsPublic = false,
            RedirectUris = new HashSet<string>(["https://app.example.com/cb"], StringComparer.Ordinal),
            PostLogoutRedirectUris = new HashSet<string>(StringComparer.Ordinal),
            AllowedTokenEndpointAuthMethods = new HashSet<string>(
                [TokenEndpointAuthMethods.None, TokenEndpointAuthMethods.ClientSecretBasic],
                StringComparer.Ordinal)
        };

        var failures = validator.Validate(client);

        failures.Should().Contain(
                f => f.Code == "client.token_endpoint_auth_methods.none_on_confidential");
    }

    // ── Two-credential cap ────────────────────────────────────────────────────────────────────────

    [Fact]
    public void Validate_passes_for_client_with_two_secrets()
    {
        var validator = MakeValidator();

        // Object initialiser to bypass CreateConfidential, which takes one secret.
        var client = new Client
        {
            ClientId = "client",
            Secrets = [FakeSecret, FakeSecret],
            IsPublic = false,
            RedirectUris = new HashSet<string>(["https://app.example.com/cb"], StringComparer.Ordinal),
            PostLogoutRedirectUris = new HashSet<string>(StringComparer.Ordinal),
            AllowedTokenEndpointAuthMethods = new HashSet<string>(
                [TokenEndpointAuthMethods.ClientSecretBasic], StringComparer.Ordinal)
        };

        var failures = validator.Validate(client);

        failures.Should().BeEmpty();
    }

    [Fact]
    public void Validate_fails_with_too_many_secrets_code_for_client_with_three_secrets()
    {
        var validator = MakeValidator();
        var client = new Client
        {
            ClientId = "client",
            Secrets = [FakeSecret, FakeSecret, FakeSecret],
            IsPublic = false,
            RedirectUris = new HashSet<string>(["https://app.example.com/cb"], StringComparer.Ordinal),
            PostLogoutRedirectUris = new HashSet<string>(StringComparer.Ordinal),
            AllowedTokenEndpointAuthMethods = new HashSet<string>(
                [TokenEndpointAuthMethods.ClientSecretBasic], StringComparer.Ordinal)
        };

        var failures = validator.Validate(client);

        failures.Should().Contain(f => f.Code == "client.credentials.too_many_secrets");
    }

    [Fact]
    public void Validate_fails_for_a_PBKDF2_secret_below_the_iteration_floor()
    {
        // The real hasher, reached the way production reaches it: through the composite, as
        // IClientSecretHasher. A fake here would prove nothing about whether the bound is live.
        var hasher = new Pbkdf2ClientSecretHasher(
            new FixedOptionsMonitor<Pbkdf2ClientSecretHasherOptions>(new Pbkdf2ClientSecretHasherOptions()));
        var validator = MakeValidator(hasher);
        var client = MakeValidConfidentialClient(
            secret: Pbkdf2ClientSecretHasher.Format(Pbkdf2ClientSecretHasher.MinIterations - 1, new byte[16], new byte[32]));

        var failures = validator.Validate(client);

        failures.Should().Contain(f => f.Code == "client.credentials.pbkdf2_iterations_below_minimum");
    }

    // ── Stored secret shape ───────────────────────────────────────────────────────────────────────

    [Fact]
    public void Validate_fails_with_null_entry_code_if_Secrets_holds_a_null()
    {
        var validator = MakeValidator();
        var client = MakeValidConfidentialClient() with { Secrets = [FakeSecret, null!] };

        var failures = validator.Validate(client);

        failures.Should().Contain(f => f.Code == "client.credentials.null_entry");
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public void Validate_fails_with_null_entry_code_if_a_secret_has_no_value(string? value)
    {
        var validator = MakeValidator();
        var client = MakeValidConfidentialClient(secret: new ClientSecret(value!));

        var failures = validator.Validate(client);

        failures.Should().Contain(f => f.Code == "client.credentials.null_entry");
    }

    [Theory]
    [InlineData("my-plaintext-secret")]
    [InlineData("$my-plaintext-secret")]
    [InlineData("$$fake$x")]
    public void Validate_fails_with_malformed_secret_code_without_quoting_the_value(string value)
    {
        var validator = MakeValidator();
        var client = MakeValidConfidentialClient(secret: new ClientSecret(value));

        var failures = validator.Validate(client);

        failures.Should().ContainSingle(f => f.Code == "client.credentials.malformed_secret")
            .Which.Message.Should().NotContain(value);
    }

    [Fact]
    public void Validate_names_the_algorithm_id_but_not_the_rest_of_the_value_when_no_hasher_declared_it()
    {
        var validator = MakeValidator();
        var client = MakeValidConfidentialClient(secret: new ClientSecret("$argon2id$v=19$m=1$c2FsdA$aGFzaA"));

        var failures = validator.Validate(client);

        failures.Should().ContainSingle(f => f.Code == "client.credentials.no_hasher")
            .Which.Message.Should().Contain("'argon2id'").And.NotContain("c2FsdA");
    }

    [Theory]
    [InlineData("$My Secret Password$x")]
    [InlineData("$an-id-that-is-far-longer-than-thirty-two-characters$x")]
    public void A_first_segment_that_cannot_be_an_algorithm_id_is_malformed_and_never_quoted(string value)
    {
        var validator = MakeValidator();
        var client = MakeValidConfidentialClient(secret: new ClientSecret(value));

        var failures = validator.Validate(client);

        failures.Should().ContainSingle(f => f.Code == "client.credentials.malformed_secret")
            .Which.Message.Should().NotContain(value[1..value.IndexOf('$', 1)]);
    }

    [Fact]
    public void A_secret_its_hasher_refuses_is_never_verified()
    {
        // A refused value can carry a work factor that would cost the host dearly to derive.
        var hasher = new RefusingCountingHasher();
        var validator = MakeValidator(hasher);
        var client = MakeValidConfidentialClient();

        var failures = validator.Validate(client);

        failures.Should().ContainSingle(f => f.Code == "test.refused");
        hasher.VerifyCalls.Should().Be(0);
    }

    private sealed class RefusingCountingHasher : IClientSecretHasher
    {
        public int VerifyCalls { get; private set; }
        public IReadOnlySet<string> AlgorithmIds { get; } = new HashSet<string> { "fake" };
        public ClientSecret Create(ReadOnlySpan<char> plaintext) => FakeSecret;

        public bool Verify(ReadOnlySpan<char> presented, ClientSecret stored)
        {
            VerifyCalls++;
            return false;
        }

        public IEnumerable<ZeeKayDaConfigurationFailure> ValidateStoredSecret(ClientSecret stored) =>
            [new("test.refused", "refused.")];
    }

    [Fact]
    public void The_two_secret_cap_counts_what_the_list_yields_not_what_it_reports()
    {
        var validator = MakeValidator();
        var client = MakeValidConfidentialClient() with
        {
            Secrets = new MiscountingList<ClientSecret>([FakeSecret, FakeSecret, FakeSecret], reportedCount: 2),
        };

        var failures = validator.Validate(client);

        failures.Should().Contain(f => f.Code == "client.credentials.too_many_secrets");
    }

    /// <summary>A store's own list that yields its items while reporting a different <c>Count</c>.</summary>
    private sealed class MiscountingList<T>(IReadOnlyList<T> items, int reportedCount) : IReadOnlyList<T>
    {
        public int Count => reportedCount;
        public T this[int index] => items[index];
        public IEnumerator<T> GetEnumerator() => items.GetEnumerator();
        System.Collections.IEnumerator System.Collections.IEnumerable.GetEnumerator() => GetEnumerator();
    }

    [Fact]
    public void One_bad_secret_refuses_the_client_even_when_its_other_secret_is_valid()
    {
        // Skipping the bad one would hide a broken rotation until the good secret is retired.
        var validator = MakeValidator();
        var client = MakeValidConfidentialClient() with { Secrets = [FakeSecret, AnySecret] };

        var failures = validator.Validate(client);

        failures.Should().ContainSingle(f => f.Code == "client.credentials.no_hasher");
    }

    [Fact]
    public void Validate_reports_no_failure_for_the_resolver_s_copy_of_a_valid_registration()
    {
        var validator = MakeValidator();
        var client = MakeValidConfidentialClient();

        var failures = validator.Validate(ClientRegistrationSnapshot.Of(client));

        failures.Should().BeEmpty();
    }

    [Fact]
    public void Validate_fails_with_no_hasher_code_if_no_hasher_declared_the_secret_s_id()
    {
        // The validator's composite only has a FakeHasher (owns "fake"). No registered hasher declared
        // "any", so the secret can never be verified — it must be rejected at registration rather
        // than failing silently at runtime as invalid_client.
        var validator = MakeValidator(hasher: new FakeHasher());

        var client = new Client
        {
            ClientId = "client",
            Secrets = [AnySecret],
            IsPublic = false,
            RedirectUris = new HashSet<string>(["https://app.example.com/cb"], StringComparer.Ordinal),
            PostLogoutRedirectUris = new HashSet<string>(StringComparer.Ordinal),
            AllowedTokenEndpointAuthMethods = new HashSet<string>(
                [TokenEndpointAuthMethods.ClientSecretBasic], StringComparer.Ordinal)
        };

        var failures = validator.Validate(client);

        failures.Should().Contain(f => f.Code == "client.credentials.no_hasher");
    }

    // ── AllowedSigningAlgorithms ──────────────────────────────────────────────────────────────────

    [Fact]
    public void Validate_passes_if_AllowedSigningAlgorithms_is_null()
    {
        var validator = MakeValidator();
        var client = MakeValidPublicClient() with { AllowedSigningAlgorithms = null };

        var failures = validator.Validate(client);

        failures.Should().BeEmpty();
    }

    [Fact]
    public void Validate_fails_with_empty_when_set_code_if_AllowedSigningAlgorithms_is_empty()
    {
        var validator = MakeValidator();
        var client = MakeValidPublicClient() with
        {
            AllowedSigningAlgorithms = new HashSet<SigningAlgorithm>()
        };

        var failures = validator.Validate(client);

        failures.Should().Contain(f => f.Code == "client.signing_algorithms.empty_when_set");
    }

    [Fact]
    public void Validate_passes_if_AllowedSigningAlgorithms_is_subset_of_server_algorithms()
    {
        var opts = new AuthorizationServerOptions { Issuer = "https://test.example.com" };
        var validator = MakeValidator(
            serverOptions: opts,
            keySet: TestSigningKeys.KeySet(SigningAlgorithm.RS256, SigningAlgorithm.ES256));

        var client = MakeValidPublicClient() with
        {
            AllowedSigningAlgorithms = new HashSet<SigningAlgorithm> { SigningAlgorithm.RS256 }
        };

        var failures = validator.Validate(client);

        failures.Should().BeEmpty();
    }

    [Fact]
    public void Validate_fails_with_not_subset_code_if_AllowedSigningAlgorithms_is_not_subset_of_server_algorithms()
    {
        var opts = new AuthorizationServerOptions { Issuer = "https://test.example.com" };
        var validator = MakeValidator(
            serverOptions: opts, keySet: TestSigningKeys.KeySet(SigningAlgorithm.RS256));

        var client = MakeValidPublicClient() with
        {
            AllowedSigningAlgorithms = new HashSet<SigningAlgorithm> { SigningAlgorithm.ES512 }
        };

        var failures = validator.Validate(client);

        failures.Should().Contain(f => f.Code == "client.signing_algorithms.not_subset");
    }

    [Fact]
    public void Validate_fails_if_AllowedSigningAlgorithms_entry_is_withheld_by_the_advertised_filter()
    {
        var opts = new AuthorizationServerOptions { Issuer = "https://test.example.com" };
        opts.IdToken.AdvertisedSigningAlgorithms = [SigningAlgorithm.RS256];
        var validator = MakeValidator(
            serverOptions: opts,
            keySet: TestSigningKeys.KeySet(SigningAlgorithm.RS256, SigningAlgorithm.ES256));

        var client = MakeValidPublicClient() with
        {
            AllowedSigningAlgorithms = new HashSet<SigningAlgorithm> { SigningAlgorithm.ES256 }
        };

        var failures = validator.Validate(client);

        failures.Should().Contain(f => f.Code == "client.signing_algorithms.not_subset",
                "the server holds an ES256 key but the operator has withheld it from discovery");
    }

    [Fact]
    public void Validate_checks_against_the_filter_alone_when_the_key_ring_has_not_read_its_source()
    {
        var opts = new AuthorizationServerOptions { Issuer = "https://test.example.com" };
        opts.IdToken.AdvertisedSigningAlgorithms = [SigningAlgorithm.RS256];
        var validator = MakeValidator(serverOptions: opts, keySet: null);

        var client = MakeValidPublicClient() with
        {
            AllowedSigningAlgorithms = new HashSet<SigningAlgorithm> { SigningAlgorithm.ES512 }
        };

        var failures = validator.Validate(client);

        failures.Should().Contain(f => f.Code == "client.signing_algorithms.not_subset");
    }

    [Fact]
    public void Validate_warns_when_the_key_ring_exists_but_has_not_read_its_source()
    {
        // A host that resolves IClientRepository before startup verification runs gets no subset
        // check at all. That window is unchecked by anything else, so it is logged rather than
        // passed over in silence.
        var opts = new AuthorizationServerOptions { Issuer = "https://test.example.com" };
        var logger = new CapturingSanitizingLogger<ClientRegistrationValidator>();
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
        var validator = MakeValidator(serverOptions: opts, withKeyRing: false);

        var client = MakeValidPublicClient() with
        {
            AllowedSigningAlgorithms = new HashSet<SigningAlgorithm> { SigningAlgorithm.ES512 }
        };

        var failures = validator.Validate(client);

        failures.Should().BeEmpty("there is nothing yet for the client's set to be a subset of");
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

        var failures = validator.Validate(client);

        failures.Should().Contain(f => f.Code == "client.allowed_scopes.blank_entry");
    }

    [Fact]
    public void Validate_fails_with_blank_entry_code_if_AllowedScopes_contains_whitespace_entry()
    {
        var validator = MakeValidator();
        var client = MakeValidPublicClient() with
        {
            AllowedScopes = new HashSet<string>(["openid", "  "], StringComparer.Ordinal)
        };

        var failures = validator.Validate(client);

        failures.Should().Contain(f => f.Code == "client.allowed_scopes.blank_entry");
    }

    // ── Claim additions ──────────────────────────────────────────────────────────────────────────

    [Fact]
    public void Validate_accepts_claim_additions_naming_claims_no_protocol_name_uses()
    {
        var validator = MakeValidator();
        var client = MakeValidPublicClient() with
        {
            AdditionalIdTokenClaims = new HashSet<string>(["tenant"], StringComparer.Ordinal),
            AdditionalUserInfoClaims = new HashSet<string>(["tenant"], StringComparer.Ordinal),
            AdditionalAccessTokenClaims = new HashSet<string>(["tenant", "department"], StringComparer.Ordinal),
        };

        var failures = validator.Validate(client);

        failures.Should().BeEmpty();
    }

    [Theory]
    [InlineData("")]
    [InlineData("  ")]
    public void Validate_fails_with_blank_entry_code_if_a_claim_addition_is_blank(string entry)
    {
        var validator = MakeValidator();
        var client = MakeValidPublicClient() with { AdditionalUserInfoClaims = new HashSet<string>(["tenant", entry], StringComparer.Ordinal) };

        var failures = validator.Validate(client);

        failures.Should().Contain(f => f.Code == "client.claim_additions.blank_entry");
    }

    [Theory]
    [InlineData("sub")]
    [InlineData("Aud")]
    [InlineData("zkd:sid")]
    public void Validate_fails_with_reserved_code_if_a_claim_addition_names_a_protocol_claim(string entry)
    {
        var validator = MakeValidator();
        var client = MakeValidPublicClient() with { AdditionalAccessTokenClaims = new HashSet<string>([entry], StringComparer.Ordinal) };

        var failures = validator.Validate(client);

        failures.Should().Contain(f => f.Code == "client.claim_additions.reserved");
    }

    [Fact]
    public void Validate_fails_with_null_code_if_a_claim_addition_collection_is_null()
    {
        var validator = MakeValidator();
        var client = MakeValidPublicClient() with { AdditionalIdTokenClaims = null! };

        var failures = validator.Validate(client);

        failures.Should().Contain(f => f.Code == "client.claim_additions.null");
    }

    // ── AllowedTokenEndpointAuthMethods ──────────────────────────────────────────────────────────

    [Fact]
    public void Validate_fails_with_not_subset_code_if_auth_method_is_not_in_server_subset()
    {
        // Default server supports only ClientSecretBasic
        var validator = MakeValidator();
        var client = new Client
        {
            ClientId = "client",
            Secrets = [FakeSecret],
            IsPublic = false,
            RedirectUris = new HashSet<string>(["https://app.example.com/cb"], StringComparer.Ordinal),
            PostLogoutRedirectUris = new HashSet<string>(StringComparer.Ordinal),
            AllowedTokenEndpointAuthMethods = new HashSet<string>(
                ["private_key_jwt"], StringComparer.Ordinal)
        };

        var failures = validator.Validate(client);

        failures.Should().Contain(f => f.Code == "client.token_endpoint_auth_methods.not_subset");
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

        var failures = validator.Validate(client);

        failures.Should().Contain(f => f.Code == "client.grant_types.undefined_value");
    }

    [Fact]
    public void Validate_fails_with_response_type_undefined_value_code_for_undefined_ResponseType()
    {
        var validator = MakeValidator();
        var client = MakeValidPublicClient() with
        {
            AllowedResponseTypes = new HashSet<ResponseType> { (ResponseType)999 }
        };

        var failures = validator.Validate(client);

        failures.Should().Contain(f => f.Code == "client.response_types.undefined_value");
    }

    [Fact]
    public void Validate_fails_with_response_mode_undefined_value_code_for_undefined_ResponseMode()
    {
        var validator = MakeValidator();
        var client = MakeValidPublicClient() with
        {
            AllowedResponseModes = new HashSet<ResponseMode> { (ResponseMode)999 }
        };

        var failures = validator.Validate(client);

        failures.Should().Contain(f => f.Code == "client.response_modes.undefined_value");
    }

    [Fact]
    public void Validate_fails_with_prompt_value_undefined_value_code_for_undefined_PromptValue()
    {
        var validator = MakeValidator();
        var client = MakeValidPublicClient() with
        {
            AllowedPromptValues = new HashSet<PromptValue> { (PromptValue)999 }
        };

        var failures = validator.Validate(client);

        failures.Should().Contain(f => f.Code == "client.prompt_values.undefined_value");
    }

    // ── Flow sets against what the server serves ───────────────────────────────────────────────

    [Fact]
    public void Validate_fails_with_grant_types_not_subset_code_for_a_grant_the_server_does_not_serve()
    {
        // The default server serves only authorization_code: a client also allowed refresh_token
        // would start fine and then have that grant refused at the token endpoint.
        var validator = MakeValidator();
        var client = MakeValidPublicClient() with
        {
            AllowedGrantTypes = new HashSet<GrantType> { GrantType.AuthorizationCode, GrantType.RefreshToken }
        };

        var failures = validator.Validate(client);

        failures.Should().ContainSingle(f =>
                f.Code == "client.grant_types.not_subset" && f.Message.Contains("'RefreshToken'", StringComparison.Ordinal));
    }

    [Fact]
    public void Validate_fails_with_response_types_not_subset_code_for_a_response_type_the_server_does_not_serve()
    {
        var options = BuildDefaultServerOptions();
        options.Response.TypesSupported = [];
        var validator = MakeValidator(serverOptions: options);

        var failures = validator.Validate(MakeValidPublicClient());

        failures.Should().ContainSingle(f => f.Code == "client.response_types.not_subset");
    }

    [Fact]
    public void Validate_fails_with_response_modes_not_subset_code_for_a_response_mode_the_server_does_not_serve()
    {
        var options = BuildDefaultServerOptions();
        options.Response.ModesSupported = [];
        var validator = MakeValidator(serverOptions: options);

        var failures = validator.Validate(MakeValidPublicClient());

        failures.Should().ContainSingle(f =>
                f.Code == "client.response_modes.not_subset" && f.Message.Contains("'Query'", StringComparison.Ordinal));
    }

    [Fact]
    public void A_client_allowed_refresh_token_without_a_grant_that_issues_one_warns_but_starts()
    {
        var options = BuildDefaultServerOptions();
        options.GrantTypesSupported.Add(GrantType.RefreshToken);
        var logger = new CapturingSanitizingLogger<ClientRegistrationValidator>();
        var validator = MakeValidator(logger: logger, serverOptions: options);
        var client = MakeValidPublicClient() with
        {
            AllowedGrantTypes = new HashSet<GrantType> { GrantType.RefreshToken },
            AllowedResponseTypes = new HashSet<ResponseType>(),
            AllowedResponseModes = new HashSet<ResponseMode>(),
        };

        var failures = validator.Validate(client);

        failures.Should().BeEmpty("a client whose code grant was withdrawn may still be draining refresh tokens");
        logger.Warnings.Should().ContainSingle(w => w.Contains("refresh_token", StringComparison.Ordinal));
    }

    [Fact]
    public void A_client_allowed_refresh_token_with_the_code_grant_does_not_warn()
    {
        var options = BuildDefaultServerOptions();
        options.GrantTypesSupported.Add(GrantType.RefreshToken);
        var logger = new CapturingSanitizingLogger<ClientRegistrationValidator>();
        var validator = MakeValidator(logger: logger, serverOptions: options);
        var client = MakeValidPublicClient() with
        {
            AllowedGrantTypes = new HashSet<GrantType> { GrantType.AuthorizationCode, GrantType.RefreshToken },
        };

        validator.Validate(client);

        logger.Warnings.Should().BeEmpty();
    }

    [Fact]
    public void A_public_client_allowed_client_credentials_fails_validation()
    {
        var options = BuildDefaultServerOptions();
        options.GrantTypesSupported.Add(GrantType.ClientCredentials);
        var validator = MakeValidator(serverOptions: options);
        var client = MakeValidPublicClient() with
        {
            AllowedGrantTypes = new HashSet<GrantType> { GrantType.AuthorizationCode, GrantType.ClientCredentials },
        };

        var failures = validator.Validate(client);

        failures.Should().ContainSingle(f => f.Code == "client.grant_types.client_credentials_on_public");
    }

    [Fact]
    public void A_confidential_client_allowed_client_credentials_passes_validation()
    {
        var options = BuildDefaultServerOptions();
        options.GrantTypesSupported.Add(GrantType.ClientCredentials);
        var validator = MakeValidator(serverOptions: options);
        var client = MakeValidConfidentialClient() with
        {
            AllowedGrantTypes = new HashSet<GrantType> { GrantType.AuthorizationCode, GrantType.ClientCredentials },
        };

        var failures = validator.Validate(client);

        failures.Should().BeEmpty();
    }

    [Fact]
    public void Validate_fails_with_grant_types_empty_code_for_a_client_allowed_no_grant()
    {
        var validator = MakeValidator();
        var client = MakeValidPublicClient() with { AllowedGrantTypes = new HashSet<GrantType>() };

        var failures = validator.Validate(client);

        failures.Should().ContainSingle(f => f.Code == "client.grant_types.empty");
    }

    [Fact]
    public void Validate_fails_with_response_types_empty_code_for_a_code_grant_client_allowed_no_response_type()
    {
        var validator = MakeValidator();
        var client = MakeValidPublicClient() with { AllowedResponseTypes = new HashSet<ResponseType>() };

        var failures = validator.Validate(client);

        failures.Should().ContainSingle(f => f.Code == "client.response_types.empty");
    }

    [Fact]
    public void Validate_fails_with_response_modes_empty_code_for_a_code_grant_client_allowed_no_response_mode()
    {
        var validator = MakeValidator();
        var client = MakeValidPublicClient() with { AllowedResponseModes = new HashSet<ResponseMode>() };

        var failures = validator.Validate(client);

        failures.Should().ContainSingle(f => f.Code == "client.response_modes.empty");
    }

    [Fact]
    public void Validate_accepts_no_response_types_or_modes_on_a_client_without_the_code_grant()
    {
        // Only the code grant goes through the authorization endpoint, and RFC 7591 §2.1 gives every
        // other grant no response type, so a client that never goes there needs no way to be
        // answered there.
        var options = BuildDefaultServerOptions();
        options.GrantTypesSupported.Add(GrantType.ClientCredentials);
        var validator = MakeValidator(serverOptions: options);
        var client = MakeValidConfidentialClient() with
        {
            AllowedGrantTypes = new HashSet<GrantType> { GrantType.ClientCredentials },
            AllowedResponseTypes = new HashSet<ResponseType>(),
            AllowedResponseModes = new HashSet<ResponseMode>(),
        };

        var failures = validator.Validate(client);

        failures.Should().BeEmpty();
    }

    [Fact]
    public void Validate_reports_an_undefined_grant_type_as_undefined_and_not_also_as_unsupported()
    {
        var validator = MakeValidator();
        var client = MakeValidPublicClient() with
        {
            AllowedGrantTypes = new HashSet<GrantType> { GrantType.AuthorizationCode, (GrantType)999 }
        };

        var failures = validator.Validate(client);

        failures.Where(f => f.Code.StartsWith("client.grant_types.", StringComparison.Ordinal))
            .Should().ContainSingle().Which.Code.Should().Be("client.grant_types.undefined_value");
    }

    [Fact]
    public void Validate_counts_the_grant_types_a_set_yields_not_the_Count_it_reports()
    {
        var validator = MakeValidator();
        var client = MakeValidPublicClient() with
        {
            AllowedGrantTypes = new MisreportingSet<GrantType>([GrantType.AuthorizationCode])
        };

        var failures = validator.Validate(client);

        failures.Should().BeEmpty("the set yields a grant, whatever Count it reports");
    }

    [Fact]
    public void Validate_finds_the_code_grant_by_enumerating_not_by_asking_the_set_whether_it_contains_it()
    {
        // The snapshot serves what the set yields, so a set that yields authorization_code while
        // denying it contains it still sends its client to the authorization endpoint.
        var validator = MakeValidator();
        var client = MakeValidPublicClient() with
        {
            AllowedGrantTypes = new MisreportingSet<GrantType>([GrantType.AuthorizationCode]),
            AllowedResponseTypes = new HashSet<ResponseType>(),
        };

        var failures = validator.Validate(client);

        failures.Should().ContainSingle(f => f.Code == "client.response_types.empty");
    }

    // ── ClientId format ───────────────────────────────────────────────────────────────────────────

    [Fact]
    public void Validate_fails_with_client_id_invalid_code_if_ClientId_contains_invalid_characters()
    {
        var validator = MakeValidator();
        var client = MakeValidPublicClient() with { ClientId = "my client!" };

        var failures = validator.Validate(client);

        failures.Should().Contain(f => f.Code == "client.client_id.invalid");
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

        var failures = validator.Validate(client);

        failures.Should().Contain(f => f.Code == "client.display_name.invalid");
    }

    [Fact]
    public void Validate_fails_with_display_name_invalid_code_if_DisplayName_is_too_long()
    {
        var validator = MakeValidator();
        var client = MakeValidPublicClient() with { DisplayName = new string('a', 201) };

        var failures = validator.Validate(client);

        failures.Should().Contain(f => f.Code == "client.display_name.invalid");
    }

    [Theory]
    [InlineData(null)]
    [InlineData("Example App")]
    [InlineData("Ångström & Söhne — 顧客ポータル")]
    public void Validate_accepts_an_absent_or_printable_DisplayName(string? displayName)
    {
        var validator = MakeValidator();
        var client = MakeValidPublicClient() with { DisplayName = displayName };

        var failures = validator.Validate(client);

        failures.Should().BeEmpty();
    }

    [Fact]
    public void Validate_fails_with_client_id_invalid_code_if_ClientId_is_too_long()
    {
        var validator = MakeValidator();
        var client = MakeValidPublicClient() with { ClientId = new string('a', 201) };

        var failures = validator.Validate(client);

        failures.Should().Contain(f => f.Code == "client.client_id.invalid");
    }

    // ── Aggregate failures ────────────────────────────────────────────────────────────────────────

    [Fact]
    public void Validate_aggregates_all_failures_for_multiple_violations()
    {
        var validator = MakeValidator();
        var client = new Client
        {
            ClientId = "my client!", // invalid client_id
            Secrets = [],
            IsPublic = false, // trinity violation: IsPublic=false, no credentials, auth methods empty
            RedirectUris = new HashSet<string>(
                ["https://app.example.com/cb#frag"], StringComparer.Ordinal), // fragment
            PostLogoutRedirectUris = new HashSet<string>(StringComparer.Ordinal),
            AllowedTokenEndpointAuthMethods = new HashSet<string>(StringComparer.Ordinal)
        };

        var failures = validator.Validate(client);

        failures.Count.Should().BeGreaterThan(1);
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

        var failures = validator.Validate(client);

        failures.Should().Contain(f => f.Code == "client.redirect_uri.invalid");
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

        var failures = validator.Validate(client);

        failures.Should().BeEmpty();
    }

    // ── ClientId — null ───────────────────────────────────────────────────────────────────────────

    [Fact]
    public void Validate_fails_with_client_id_invalid_code_if_ClientId_is_null()
    {
        var validator = MakeValidator();
        var client = MakeValidPublicClient() with { ClientId = null! };

        var failures = validator.Validate(client);

        failures.Should().Contain(f => f.Code == "client.client_id.invalid");
    }

    // ── AllowedTokenEndpointAuthMethods — invalid entries ────────────────────────────────────────

    [Fact]
    public void Validate_fails_with_invalid_entry_code_if_auth_method_has_leading_whitespace()
    {
        var validator = MakeValidator();
        var client = new Client
        {
            ClientId = "client",
            Secrets = [FakeSecret],
            IsPublic = false,
            RedirectUris = new HashSet<string>(["https://app.example.com/cb"], StringComparer.Ordinal),
            PostLogoutRedirectUris = new HashSet<string>(StringComparer.Ordinal),
            AllowedTokenEndpointAuthMethods = new HashSet<string>(
                [" client_secret_basic"], StringComparer.Ordinal)
        };

        var failures = validator.Validate(client);

        failures.Should().Contain(
                f => f.Code == "client.token_endpoint_auth_methods.invalid_entry");
    }

    [Fact]
    public void Validate_fails_with_invalid_entry_code_if_auth_method_has_control_character()
    {
        var validator = MakeValidator();
        var client = new Client
        {
            ClientId = "client",
            Secrets = [FakeSecret],
            IsPublic = false,
            RedirectUris = new HashSet<string>(["https://app.example.com/cb"], StringComparer.Ordinal),
            PostLogoutRedirectUris = new HashSet<string>(StringComparer.Ordinal),
            AllowedTokenEndpointAuthMethods = new HashSet<string>(
                ["client\x01secret"], StringComparer.Ordinal)
        };

        var failures = validator.Validate(client);

        failures.Should().Contain(
                f => f.Code == "client.token_endpoint_auth_methods.invalid_entry");
    }

    // ── AllowedTokenEndpointAuthMethods — duplicate ───────────────────────────────────────────────

    [Fact]
    public void Validate_fails_with_duplicate_code_for_duplicate_auth_method()
    {
        // IReadOnlySet<string> deduplicates, so we use a custom stub that allows duplicate entries.
        var validator = MakeValidator();
        var client = new Client
        {
            ClientId = "client",
            Secrets = [FakeSecret],
            IsPublic = false,
            RedirectUris = new HashSet<string>(["https://app.example.com/cb"], StringComparer.Ordinal),
            PostLogoutRedirectUris = new HashSet<string>(StringComparer.Ordinal),
            AllowedTokenEndpointAuthMethods = new DuplicatingSet(
                TokenEndpointAuthMethods.ClientSecretBasic,
                TokenEndpointAuthMethods.ClientSecretBasic)
        };

        var failures = validator.Validate(client);

        failures.Should().Contain(
                f => f.Code == "client.token_endpoint_auth_methods.duplicate");
    }

    // ── AllowedTokenEndpointAuthMethods — ToWireFormat arms ──────────────────────────────────────

    [Fact]
    public void Validate_failure_message_contains_wire_string_if_ClientSecretJwt_is_not_in_server_subset()
    {
        var validator = MakeValidator(); // default server: client_secret_basic + none
        var client = new Client
        {
            ClientId = "client",
            Secrets = [FakeSecret],
            IsPublic = false,
            RedirectUris = new HashSet<string>(["https://app.example.com/cb"], StringComparer.Ordinal),
            PostLogoutRedirectUris = new HashSet<string>(StringComparer.Ordinal),
            AllowedTokenEndpointAuthMethods = new HashSet<string>(
                ["client_secret_jwt"], StringComparer.Ordinal)
        };

        var failures = validator.Validate(client);

        failures.Should().Contain(f =>
                f.Code == "client.token_endpoint_auth_methods.not_subset" &&
                f.Message.Contains("client_secret_jwt"));
    }

    [Fact]
    public void Validate_failure_message_contains_wire_string_if_ClientSecretPost_is_not_in_server_subset()
    {
        // Explicitly configure a server that only supports client_secret_basic so that a client
        // registering client_secret_post fails the subset check.
        var serverOptions = new AuthorizationServerOptions { Issuer = "https://test.example.com" };
        serverOptions.TokenEndpoint.AdvertisedAuthMethods =
            [TokenEndpointAuthMethods.ClientSecretBasic, TokenEndpointAuthMethods.None];
        var validator = MakeValidator(serverOptions: serverOptions);
        var client = new Client
        {
            ClientId = "client",
            Secrets = [FakeSecret],
            IsPublic = false,
            RedirectUris = new HashSet<string>(["https://app.example.com/cb"], StringComparer.Ordinal),
            PostLogoutRedirectUris = new HashSet<string>(StringComparer.Ordinal),
            AllowedTokenEndpointAuthMethods = new HashSet<string>(
                ["client_secret_post"], StringComparer.Ordinal)
        };

        var failures = validator.Validate(client);

        failures.Should().Contain(f =>
                f.Code == "client.token_endpoint_auth_methods.not_subset" &&
                f.Message.Contains("client_secret_post"));
    }

    [Fact]
    public void Validate_failure_message_names_the_filter_for_a_public_client_if_the_filter_withholds_None()
    {
        var opts = new AuthorizationServerOptions { Issuer = "https://test.example.com" };
        opts.TokenEndpoint.AdvertisedAuthMethods = [TokenEndpointAuthMethods.ClientSecretBasic];
        var validator = MakeValidator(serverOptions: opts);
        var client = Client.CreatePublic(
            "client",
            ["https://app.example.com/cb"],
            [],
            ["openid"]);

        var failures = validator.Validate(client);

        failures.Should().Contain(f =>
                f.Code == "client.token_endpoint_auth_methods.not_subset" &&
                f.Message.Contains("none") &&
                f.Message.Contains("TokenEndpoint.AdvertisedAuthMethods"));
    }

    [Fact]
    public void Validate_passes_a_public_client_with_no_filter_configured()
    {
        var validator = MakeValidator(serverOptions: new AuthorizationServerOptions { Issuer = "https://test.example.com" });

        var failures = validator.Validate(MakeValidPublicClient());

        failures.Should().BeEmpty("'none' is advertised by default, so a public client needs no server-wide opt-in");
    }

    // ── Credential registration constraints ──────────────────────────────────────────────────────

    /// <summary>
    /// A hasher that owns the <c>fake</c> id and returns a predictable failure from
    /// <see cref="IClientSecretHasher.ValidateStoredSecret"/>. Used to verify the validator
    /// delegates to the hasher rather than implementing its own algorithm-specific checks.
    /// </summary>
    private sealed class RegistrationFailingHasher : IClientSecretHasher
    {
        public IReadOnlySet<string> AlgorithmIds { get; } = new HashSet<string> { "fake" };
        public bool Verify(ReadOnlySpan<char> presented, ClientSecret stored) => false;
        public ClientSecret Create(ReadOnlySpan<char> plaintext) => FakeSecret;

        public IEnumerable<ZeeKayDaConfigurationFailure> ValidateStoredSecret(ClientSecret stored)
        {
            yield return new ZeeKayDaConfigurationFailure("test.fake_constraint", "failed fake constraint.");
        }
    }

    [Fact]
    public void Validate_aggregates_failures_from_the_hasher_s_ValidateStoredSecret_with_the_client_id()
    {
        var validator = MakeValidator(new RegistrationFailingHasher());
        var client = MakeValidConfidentialClient();

        var failures = validator.Validate(client);

        failures.Should().ContainSingle(f =>
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

    // ── AccessTokenLifetime / IdTokenLifetime ─────────────────────────────────────────────────────

    [Fact]
    public void Validate_passes_when_token_lifetime_overrides_are_null()
    {
        var client = MakeValidPublicClient() with { AccessTokenLifetime = null, IdTokenLifetime = null };

        var failures = MakeValidator().Validate(client);

        failures.Should().BeEmpty("null inherits the server value");
    }

    [Fact]
    public void Validate_passes_when_token_lifetime_overrides_are_positive()
    {
        var client = MakeValidPublicClient() with
        {
            AccessTokenLifetime = TimeSpan.FromMinutes(10),
            IdTokenLifetime = TimeSpan.FromMinutes(1),
        };

        var failures = MakeValidator().Validate(client);

        failures.Should().BeEmpty();
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    public void Validate_fails_when_AccessTokenLifetime_override_is_not_positive(int seconds)
    {
        var client = MakeValidPublicClient() with { AccessTokenLifetime = TimeSpan.FromSeconds(seconds) };

        var failures = MakeValidator().Validate(client);

        failures.Should().ContainSingle(f => f.Code == "client.token_lifetime.not_positive")
            .Which.Message.Should().Contain("AccessTokenLifetime");
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    public void Validate_fails_when_IdTokenLifetime_override_is_not_positive(int seconds)
    {
        var client = MakeValidPublicClient() with { IdTokenLifetime = TimeSpan.FromSeconds(seconds) };

        var failures = MakeValidator().Validate(client);

        failures.Should().ContainSingle(f => f.Code == "client.token_lifetime.not_positive")
            .Which.Message.Should().Contain("IdTokenLifetime");
    }

    [Fact]
    public void Validate_warns_but_passes_when_a_token_lifetime_override_exceeds_the_family_ceiling()
    {
        var opts = BuildDefaultServerOptions();
        opts.TokenEndpoint.AbsoluteFamilyLifetime = TimeSpan.FromDays(30);
        var logger = new CapturingSanitizingLogger<ClientRegistrationValidator>();
        var client = MakeValidPublicClient() with { AccessTokenLifetime = TimeSpan.FromDays(31) };

        var failures = MakeValidator(logger: logger, serverOptions: opts).Validate(client);

        failures.Should().BeEmpty("a custom repository may validate on resolution, where a failure would take the request down");
        logger.Warnings.Should().ContainSingle(w => w.Contains("AccessTokenLifetime") && w.Contains("AbsoluteFamilyLifetime"));
    }

    [Fact]
    public void Validate_does_not_warn_when_a_token_lifetime_override_is_within_the_family_ceiling()
    {
        var logger = new CapturingSanitizingLogger<ClientRegistrationValidator>();
        var client = MakeValidPublicClient() with { AccessTokenLifetime = TimeSpan.FromHours(2), IdTokenLifetime = TimeSpan.FromHours(2) };

        MakeValidator(logger: logger).Validate(client);

        logger.Warnings.Should().NotContain(w => w.Contains("Lifetime"));
    }

    // ── AllowedSigningAlgorithms must include the key that signs ──────────────────────────────────

    [Fact]
    public void A_client_whose_allowed_algorithms_exclude_the_current_signing_key_fails_registration()
    {
        // ES256 is advertised (a published key carries it), so the subset rule passes; but the key
        // that signs today is RS256, and a client pinned to ES256 could never be issued an ID token.
        var keySet = TestSigningKeys.KeySet(SigningAlgorithm.RS256, SigningAlgorithm.ES256);
        var validator = MakeValidator(keySet: keySet);
        var client = MakeValidPublicClient() with { AllowedSigningAlgorithms = new HashSet<SigningAlgorithm> { SigningAlgorithm.ES256 } };

        var failures = validator.Validate(client);

        failures.Should().ContainSingle(f => f.Code == "client.signing_algorithms.excludes_signing_key");
    }

    [Fact]
    public void A_client_whose_allowed_algorithms_include_the_current_signing_key_passes()
    {
        var keySet = TestSigningKeys.KeySet(SigningAlgorithm.RS256, SigningAlgorithm.ES256);
        var validator = MakeValidator(keySet: keySet);
        var client = MakeValidPublicClient() with { AllowedSigningAlgorithms = new HashSet<SigningAlgorithm> { SigningAlgorithm.RS256 } };

        var failures = validator.Validate(client);

        failures.Should().BeEmpty();
    }

    // ── InitiateLoginUri ──────────────────────────────────────────────────────────────────────────

    [Fact]
    public void Validate_passes_for_an_https_initiate_login_uri()
    {
        var validator = MakeValidator();
        var client = MakeValidPublicClient() with { InitiateLoginUri = "https://app.example.com/login?source=idp" };

        var failures = validator.Validate(client);

        failures.Should().BeEmpty();
    }

    [Theory]
    [InlineData("not a uri", "client.initiate_login_uri.invalid")]
    [InlineData("/relative/login", "client.initiate_login_uri.invalid")]
    [InlineData("https://app.example.com/lo gin", "client.initiate_login_uri.invalid")]
    [InlineData("https://app.example.com/login\u0007", "client.initiate_login_uri.invalid")]
    [InlineData("https:/login", "client.initiate_login_uri.invalid")]
    [InlineData("https:///login", "client.initiate_login_uri.invalid")]
    [InlineData("https://:443/login", "client.initiate_login_uri.invalid")]
    [InlineData("http://app.example.com/login", "client.initiate_login_uri.scheme")]
    [InlineData("http://127.0.0.1/login", "client.initiate_login_uri.scheme")]
    [InlineData("myapp.scheme://login", "client.initiate_login_uri.scheme")]
    [InlineData("https://app.example.com/login#x", "client.initiate_login_uri.fragment")]
    [InlineData("https://user@app.example.com/login", "client.initiate_login_uri.userinfo")]
    [InlineData("https://[fe80::1%25eth0]/login", "client.initiate_login_uri.ipv6_zone_id")]
    [InlineData("https://app.example.com/a/../login", "client.initiate_login_uri.path_traversal")]
    public void Validate_fails_for_an_initiate_login_uri_the_framework_must_not_send_a_browser_to(string uri, string code)
    {
        var validator = MakeValidator();
        var client = MakeValidPublicClient() with { InitiateLoginUri = System.Text.RegularExpressions.Regex.Unescape(uri) };

        var failures = validator.Validate(client);

        failures.Should().Contain(f => f.Code == code);
    }
}
