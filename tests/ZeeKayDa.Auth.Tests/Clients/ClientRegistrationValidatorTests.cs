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

    private sealed class FakeSecret : IClientSecret { public IClientCredential Snapshot() => new FakeSecret(); }

    private sealed class AnySecret : IClientSecret { public IClientCredential Snapshot() => new AnySecret(); }

    // The credentials below are deliberately not secrets: the snapshot rule applies to every
    // credential, including ones no hasher will ever see.

    private sealed class SelfReturningCredential : IClientCredential
    {
        public IClientCredential Snapshot() => this;
    }

    private sealed class NullReturningCredential : IClientCredential
    {
        public IClientCredential Snapshot() => null!;
    }

    private sealed class ThrowingSnapshotCredential(Exception exception) : IClientCredential
    {
        public IClientCredential Snapshot() => throw exception;
    }

    private sealed class CopyingCredential : IClientCredential
    {
        public IClientCredential Snapshot() => new CopyingCredential();
    }

    /// <summary>A secret whose copy is a credential but no longer a secret.</summary>
    private sealed class DemotingSecret : IClientSecret
    {
        public IClientCredential Snapshot() => new CopyingCredential();
    }

    /// <summary>A secret <see cref="RetypingHasher"/> handles, whose copy no hasher handles.</summary>
    private sealed class RetypingSecret : IClientSecret
    {
        public IClientCredential Snapshot() => new AnySecret();
    }

    /// <summary>A stored secret whose copy accepts an empty secret, and whose copy's copy does not.</summary>
    private sealed class StoredSecret : IClientSecret
    {
        public IClientCredential Snapshot() => new EmptyAcceptingCopy();
    }

    private sealed class EmptyAcceptingCopy : IClientSecret
    {
        public IClientCredential Snapshot() => new SafeCopy();
    }

    private sealed class SafeCopy : IClientSecret
    {
        public IClientCredential Snapshot() => new SafeCopy();
    }

    /// <summary>Handles all three generations; only <see cref="EmptyAcceptingCopy"/> verifies anything.</summary>
    private sealed class GenerationHasher : IClientSecretHasher
    {
        public bool CanHandle(IClientSecret secret) => secret is StoredSecret or EmptyAcceptingCopy or SafeCopy;
        public bool Verify(IClientSecret stored, ReadOnlySpan<char> presented) => stored is EmptyAcceptingCopy;
        public IClientSecret Create(ReadOnlySpan<char> plaintext) => new SafeCopy();
    }

    private sealed class RetypingHasher : IClientSecretHasher
    {
        public bool CanHandle(IClientSecret secret) => secret is RetypingSecret;
        public bool Verify(IClientSecret stored, ReadOnlySpan<char> presented) => false;
        public IClientSecret Create(ReadOnlySpan<char> plaintext) => new RetypingSecret();
    }

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

    // ── PKCE opt-out ──────────────────────────────────────────────────────────────────────────────

    [Fact]
    public void A_public_client_cannot_be_permitted_to_omit_pkce()
    {
        var validator = MakeValidator();
        var client = MakeValidPublicClient() with { RequirePkce = false };

        var act = () => validator.Validate(client);

        act.Should().Throw<ZeeKayDaConfigurationException>()
            .Which.AggregatedFailures.Should().Contain(f => f.Code == "client.require_pkce.disabled_on_public");
    }

    [Fact]
    public void A_confidential_client_may_be_permitted_to_omit_pkce()
    {
        var validator = MakeValidator();
        var client = MakeValidConfidentialClient() with { RequirePkce = false };

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
    public void Validate_passes_without_log_warning_for_HTTPS_localhost_redirect_uri()
    {
        // The localhost advisory warning (RFC 8252 §8.3) is for native apps' http loopback
        // redirects. https://localhost is a web client on a dev certificate, where TLS already
        // rules out the name-resolution risk the advice is about.
        var logger = new CapturingLogger();
        var validator = MakeValidator(logger: logger);
        var client = MakeValidPublicClient() with
        {
            RedirectUris = new HashSet<string>(["https://localhost:5002/signin-oidc"], StringComparer.Ordinal)
        };

        var act = () => validator.Validate(client);

        act.Should().NotThrow();
        logger.Warnings.Should().NotContain(w => w.Contains("localhost"));
    }

    [Fact]
    public void Validate_emits_log_warning_for_HTTP_localhost_post_logout_redirect_uri_but_not_HTTPS()
    {
        var logger = new CapturingLogger();
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
    public void Validate_fails_with_count_exceeded_code_if_redirect_uri_set_under_reports_its_count()
    {
        var validator = MakeValidator();
        var uris = Enumerable.Range(1, 33).Select(i => $"https://app.example.com/cb{i}");
        var client = MakeValidPublicClient() with
        {
            RedirectUris = new MiscountingSet(uris, reportedCount: 1)
        };

        var act = () => validator.Validate(client);

        act.Should().Throw<ZeeKayDaConfigurationException>()
            .Which.AggregatedFailures.Should().Contain(f => f.Code == "client.redirect_uri.count_exceeded");
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
    public void Validate_fails_with_trinity_violation_code_if_auth_method_set_under_reports_its_count()
    {
        var validator = MakeValidator();
        var client = MakeValidPublicClient() with
        {
            AllowedTokenEndpointAuthMethods = new MiscountingSet(
                [TokenEndpointAuthMethods.None, TokenEndpointAuthMethods.ClientSecretBasic],
                reportedCount: 1)
        };

        var act = () => validator.Validate(client);

        act.Should().Throw<ZeeKayDaConfigurationException>()
            .Which.AggregatedFailures.Should().Contain(f => f.Code == "client.is_public.trinity_violation");
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

    [Fact]
    public void Validate_fails_for_a_PBKDF2_credential_below_the_iteration_floor()
    {
        // The real hasher, reached the way production reaches it: through the composite, as
        // IClientSecretHasher. A fake here would prove nothing about whether the bound is live.
        var hasher = new Pbkdf2ClientSecretHasher(
            Options.Create(new Pbkdf2ClientSecretHasherOptions()),
            NullSanitizingLogger<Pbkdf2ClientSecretHasher>.Instance);
        var validator = MakeValidator(hasher);
        var client = MakeValidConfidentialClient(
            secret: new Pbkdf2ClientSecret(Pbkdf2ClientSecretHasher.MinIterations - 1, new byte[16], new byte[32]));

        var act = () => validator.Validate(client);

        act.Should().Throw<ZeeKayDaConfigurationException>()
            .Which.AggregatedFailures.Should().Contain(f => f.Code == "client.credentials.pbkdf2_iterations_below_minimum");
    }

    // ── Credential snapshots ──────────────────────────────────────────────────────────────────────

    // The resolver validates a copy of the registration and then authenticates the client against
    // that copy. A credential whose Snapshot() hands back itself, or nothing, would leave the store's
    // instance in the copy, where the store can still change it after the verdict. This rule catches
    // it on the store's instance, at startup and at a custom store's write time; at request time the
    // snapshot refuses such a credential itself (ValidatedClientResolverTests).

    [Fact]
    public void Validate_fails_with_not_copied_code_if_a_credential_s_Snapshot_returns_itself()
    {
        var failure = NotCopiedFailure(new SelfReturningCredential());

        failure.Message.Should().Contain("SelfReturningCredential").And.Contain("returned the same instance");
    }

    [Fact]
    public void Validate_fails_with_not_copied_code_if_a_credential_s_Snapshot_returns_null()
    {
        var failure = NotCopiedFailure(new NullReturningCredential());

        failure.Message.Should().Contain("NullReturningCredential").And.Contain("returned null");
    }

    [Fact]
    public void Validate_names_the_exception_but_not_its_message_if_a_credential_s_Snapshot_throws()
    {
        // A throw becomes a named startup failure rather than an unexplained exception, and the
        // message is left out because a credential's own exception may carry the credential's data.
        var credential = new ThrowingSnapshotCredential(new InvalidOperationException("salt=0badc0de"));

        var failure = NotCopiedFailure(credential);

        failure.Message.Should().Contain("threw InvalidOperationException").And.NotContain("0badc0de");
    }

    [Fact]
    public void Validate_fails_with_not_copied_code_if_a_PBKDF2_credential_has_no_salt()
    {
        // The built-in copy cannot copy a missing array. Before credentials were copied, such a
        // registration passed startup and then failed every request as an unknown client.
        var failure = NotCopiedFailure(new Pbkdf2ClientSecret(600_000, null!, new byte[32]));

        failure.Message.Should().Contain("Pbkdf2ClientSecret").And.Contain("threw");
    }

    [Fact]
    public void Validate_reports_a_configuration_failure_thrown_by_Snapshot_by_its_type_only()
    {
        // Even the framework's own exception type is not trusted here: Snapshot() belongs to the
        // credential, and a message it composed may carry the credential's data into the log.
        var credential = new ThrowingSnapshotCredential(new ZeeKayDaConfigurationException(
            new ZeeKayDaConfigurationFailure("custom.credential.unreadable", "Cannot copy salt=0badc0de.")));

        var failure = NotCopiedFailure(credential);

        failure.Message.Should().Contain("threw ZeeKayDaConfigurationException").And.NotContain("0badc0de");
    }

    [Fact]
    public void Validate_fails_with_null_entry_code_if_Credentials_holds_a_null()
    {
        // The other credential rules filter by type and skip a null, so without this the
        // registration passed startup as confidential and then failed every lookup unexplained.
        var validator = MakeValidator();
        var client = MakeValidConfidentialClient() with { Credentials = [new FakeSecret(), null!] };

        var act = () => validator.Validate(client);

        act.Should().Throw<ZeeKayDaConfigurationException>()
            .Which.AggregatedFailures.Should().Contain(f => f.Code == "client.credentials.null_entry");
    }

    [Fact]
    public void Validate_fails_with_not_copied_code_if_a_secret_s_Snapshot_is_not_a_secret()
    {
        // The copy is what the client is authenticated against. A secret that copies into some other
        // kind of credential would silently leave the client with no secret at all.
        var failure = NotCopiedFailure(new DemotingSecret());

        failure.Message.Should().Contain("DemotingSecret").And.Contain("which is not an IClientSecret");
    }

    [Fact]
    public void Validate_fails_with_no_hasher_code_if_a_secret_s_Snapshot_returns_a_type_no_hasher_handles()
    {
        // The secret rules run on the copy, which is what the resolver serves. Run on the store's
        // instance, this registration passed startup — its hasher handles the original — and then
        // failed every lookup, because nothing handles the copy.
        var validator = MakeValidator(hasher: new RetypingHasher());
        var client = MakeValidConfidentialClient(secret: new RetypingSecret());

        var act = () => validator.Validate(client);

        act.Should().Throw<ZeeKayDaConfigurationException>()
            .Which.AggregatedFailures.Should().ContainSingle(f => f.Code == "client.credentials.no_hasher")
            .Which.Message.Should().Contain(nameof(AnySecret));
    }

    [Fact]
    public void Validate_checks_the_resolver_s_copy_itself_rather_than_copying_it_again()
    {
        // The client is authenticated against the copy the snapshot holds. Copying that copy again
        // and checking the result would approve a second copy while the first is served — here, a
        // first copy that accepts an empty secret behind a second copy that does not.
        var validator = MakeValidator(hasher: new GenerationHasher());
        var client = MakeValidConfidentialClient(secret: new StoredSecret());

        var act = () => validator.Validate(ClientRegistrationSnapshot.Of(client));

        act.Should().Throw<ZeeKayDaConfigurationException>()
            .Which.AggregatedFailures.Should().Contain(f => f.Code == "client.credentials.empty_secret_accepted");
    }

    [Fact]
    public void Validate_does_not_throw_on_the_resolver_s_copy_of_a_valid_registration()
    {
        var validator = MakeValidator();
        var client = MakeValidConfidentialClient();

        var act = () => validator.Validate(ClientRegistrationSnapshot.Of(client));

        act.Should().NotThrow();
    }

    private static ZeeKayDaConfigurationFailure NotCopiedFailure(IClientCredential credential)
    {
        var validator = MakeValidator();
        var client = MakeValidConfidentialClient() with { Credentials = [new FakeSecret(), credential] };

        var act = () => validator.Validate(client);

        return act.Should().Throw<ZeeKayDaConfigurationException>()
            .Which.AggregatedFailures.Should().ContainSingle(f => f.Code == "client.credentials.not_copied")
            .Subject;
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

    // ── Claim additions ──────────────────────────────────────────────────────────────────────────

    [Fact]
    public void Validate_accepts_claim_additions_naming_claims_no_protocol_name_uses()
    {
        var validator = MakeValidator();
        var client = MakeValidPublicClient() with
        {
            AdditionalIdTokenClaims = ["tenant"],
            AdditionalUserInfoClaims = ["tenant"],
            AdditionalAccessTokenClaims = ["tenant", "department"],
        };

        var act = () => validator.Validate(client);

        act.Should().NotThrow();
    }

    [Theory]
    [InlineData("")]
    [InlineData("  ")]
    public void Validate_fails_with_blank_entry_code_if_a_claim_addition_is_blank(string entry)
    {
        var validator = MakeValidator();
        var client = MakeValidPublicClient() with { AdditionalUserInfoClaims = ["tenant", entry] };

        var act = () => validator.Validate(client);

        act.Should().Throw<ZeeKayDaConfigurationException>()
            .Which.AggregatedFailures.Should().Contain(f => f.Code == "client.claim_additions.blank_entry");
    }

    [Theory]
    [InlineData("sub")]
    [InlineData("Aud")]
    [InlineData("zkd:sid")]
    public void Validate_fails_with_reserved_code_if_a_claim_addition_names_a_protocol_claim(string entry)
    {
        var validator = MakeValidator();
        var client = MakeValidPublicClient() with { AdditionalAccessTokenClaims = [entry] };

        var act = () => validator.Validate(client);

        act.Should().Throw<ZeeKayDaConfigurationException>()
            .Which.AggregatedFailures.Should().Contain(f => f.Code == "client.claim_additions.reserved");
    }

    [Fact]
    public void Validate_fails_with_null_code_if_a_claim_addition_collection_is_null()
    {
        var validator = MakeValidator();
        var client = MakeValidPublicClient() with { AdditionalIdTokenClaims = null! };

        var act = () => validator.Validate(client);

        act.Should().Throw<ZeeKayDaConfigurationException>()
            .Which.AggregatedFailures.Should().Contain(f => f.Code == "client.claim_additions.null");
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

        var act = () => validator.Validate(client);

        act.Should().Throw<ZeeKayDaConfigurationException>()
            .Which.AggregatedFailures.Should().ContainSingle(f =>
                f.Code == "client.grant_types.not_subset" && f.Message.Contains("'RefreshToken'", StringComparison.Ordinal));
    }

    [Fact]
    public void Validate_fails_with_response_types_not_subset_code_for_a_response_type_the_server_does_not_serve()
    {
        var options = BuildDefaultServerOptions();
        options.Response.TypesSupported = [];
        var validator = MakeValidator(serverOptions: options);

        var act = () => validator.Validate(MakeValidPublicClient());

        act.Should().Throw<ZeeKayDaConfigurationException>()
            .Which.AggregatedFailures.Should().ContainSingle(f => f.Code == "client.response_types.not_subset");
    }

    [Fact]
    public void Validate_fails_with_response_modes_not_subset_code_for_form_post_on_a_server_serving_only_query()
    {
        // The authorization endpoint answers only in the query string, so a client allowed
        // form_post is promised a mode nothing delivers.
        var validator = MakeValidator();
        var client = MakeValidPublicClient() with
        {
            AllowedResponseModes = new HashSet<ResponseMode> { ResponseMode.Query, ResponseMode.FormPost }
        };

        var act = () => validator.Validate(client);

        act.Should().Throw<ZeeKayDaConfigurationException>()
            .Which.AggregatedFailures.Should().ContainSingle(f =>
                f.Code == "client.response_modes.not_subset" && f.Message.Contains("'FormPost'", StringComparison.Ordinal));
    }

    [Fact]
    public void Validate_fails_with_grant_types_empty_code_for_a_client_allowed_no_grant()
    {
        var validator = MakeValidator();
        var client = MakeValidPublicClient() with { AllowedGrantTypes = new HashSet<GrantType>() };

        var act = () => validator.Validate(client);

        act.Should().Throw<ZeeKayDaConfigurationException>()
            .Which.AggregatedFailures.Should().ContainSingle(f => f.Code == "client.grant_types.empty");
    }

    [Fact]
    public void Validate_fails_with_response_types_empty_code_for_a_code_grant_client_allowed_no_response_type()
    {
        var validator = MakeValidator();
        var client = MakeValidPublicClient() with { AllowedResponseTypes = new HashSet<ResponseType>() };

        var act = () => validator.Validate(client);

        act.Should().Throw<ZeeKayDaConfigurationException>()
            .Which.AggregatedFailures.Should().ContainSingle(f => f.Code == "client.response_types.empty");
    }

    [Fact]
    public void Validate_fails_with_response_modes_empty_code_for_a_code_grant_client_allowed_no_response_mode()
    {
        var validator = MakeValidator();
        var client = MakeValidPublicClient() with { AllowedResponseModes = new HashSet<ResponseMode>() };

        var act = () => validator.Validate(client);

        act.Should().Throw<ZeeKayDaConfigurationException>()
            .Which.AggregatedFailures.Should().ContainSingle(f => f.Code == "client.response_modes.empty");
    }

    [Fact]
    public void Validate_accepts_no_response_types_or_modes_on_a_client_without_the_code_grant()
    {
        // Only the code grant goes through the authorization endpoint (RFC 7591 §2.1), so a client
        // that never goes there needs no way to be answered there.
        var options = BuildDefaultServerOptions();
        options.GrantTypesSupported.Add(GrantType.RefreshToken);
        var validator = MakeValidator(serverOptions: options);
        var client = MakeValidPublicClient() with
        {
            AllowedGrantTypes = new HashSet<GrantType> { GrantType.RefreshToken },
            AllowedResponseTypes = new HashSet<ResponseType>(),
            AllowedResponseModes = new HashSet<ResponseMode>(),
        };

        var act = () => validator.Validate(client);

        act.Should().NotThrow();
    }

    [Fact]
    public void Validate_reports_an_undefined_grant_type_as_undefined_and_not_also_as_unsupported()
    {
        var validator = MakeValidator();
        var client = MakeValidPublicClient() with
        {
            AllowedGrantTypes = new HashSet<GrantType> { GrantType.AuthorizationCode, (GrantType)999 }
        };

        var act = () => validator.Validate(client);

        act.Should().Throw<ZeeKayDaConfigurationException>()
            .Which.AggregatedFailures.Where(f => f.Code.StartsWith("client.grant_types.", StringComparison.Ordinal))
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

        var act = () => validator.Validate(client);

        act.Should().NotThrow("the set yields a grant, whatever Count it reports");
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

        var act = () => validator.Validate(client);

        act.Should().Throw<ZeeKayDaConfigurationException>()
            .Which.AggregatedFailures.Should().ContainSingle(f => f.Code == "client.response_types.empty");
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

    // ── AccessTokenLifetime / IdTokenLifetime ─────────────────────────────────────────────────────

    [Fact]
    public void Validate_passes_when_token_lifetime_overrides_are_null()
    {
        var client = MakeValidPublicClient() with { AccessTokenLifetime = null, IdTokenLifetime = null };

        var act = () => MakeValidator().Validate(client);

        act.Should().NotThrow("null inherits the server value");
    }

    [Fact]
    public void Validate_passes_when_token_lifetime_overrides_are_positive()
    {
        var client = MakeValidPublicClient() with
        {
            AccessTokenLifetime = TimeSpan.FromMinutes(10),
            IdTokenLifetime = TimeSpan.FromMinutes(1),
        };

        var act = () => MakeValidator().Validate(client);

        act.Should().NotThrow();
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    public void Validate_fails_when_AccessTokenLifetime_override_is_not_positive(int seconds)
    {
        var client = MakeValidPublicClient() with { AccessTokenLifetime = TimeSpan.FromSeconds(seconds) };

        var act = () => MakeValidator().Validate(client);

        act.Should().Throw<ZeeKayDaConfigurationException>()
            .Which.AggregatedFailures.Should().ContainSingle(f => f.Code == "client.token_lifetime.not_positive")
            .Which.Message.Should().Contain("AccessTokenLifetime");
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    public void Validate_fails_when_IdTokenLifetime_override_is_not_positive(int seconds)
    {
        var client = MakeValidPublicClient() with { IdTokenLifetime = TimeSpan.FromSeconds(seconds) };

        var act = () => MakeValidator().Validate(client);

        act.Should().Throw<ZeeKayDaConfigurationException>()
            .Which.AggregatedFailures.Should().ContainSingle(f => f.Code == "client.token_lifetime.not_positive")
            .Which.Message.Should().Contain("IdTokenLifetime");
    }

    [Fact]
    public void Validate_warns_but_passes_when_a_token_lifetime_override_exceeds_the_family_ceiling()
    {
        var opts = BuildDefaultServerOptions();
        opts.TokenEndpoint.AbsoluteFamilyLifetime = TimeSpan.FromDays(30);
        var logger = new CapturingLogger();
        var client = MakeValidPublicClient() with { AccessTokenLifetime = TimeSpan.FromDays(31) };

        var act = () => MakeValidator(logger: logger, serverOptions: opts).Validate(client);

        act.Should().NotThrow("a custom repository may validate on resolution, where a failure would take the request down");
        logger.Warnings.Should().ContainSingle(w => w.Contains("AccessTokenLifetime") && w.Contains("AbsoluteFamilyLifetime"));
    }

    [Fact]
    public void Validate_does_not_warn_when_a_token_lifetime_override_is_within_the_family_ceiling()
    {
        var logger = new CapturingLogger();
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

        var act = () => validator.Validate(client);

        act.Should().Throw<ZeeKayDaConfigurationException>()
            .Which.AggregatedFailures.Should().ContainSingle(f => f.Code == "client.signing_algorithms.excludes_signing_key");
    }

    [Fact]
    public void A_client_whose_allowed_algorithms_include_the_current_signing_key_passes()
    {
        var keySet = TestSigningKeys.KeySet(SigningAlgorithm.RS256, SigningAlgorithm.ES256);
        var validator = MakeValidator(keySet: keySet);
        var client = MakeValidPublicClient() with { AllowedSigningAlgorithms = new HashSet<SigningAlgorithm> { SigningAlgorithm.RS256 } };

        var act = () => validator.Validate(client);

        act.Should().NotThrow();
    }

    // ── InitiateLoginUri ──────────────────────────────────────────────────────────────────────────

    [Fact]
    public void Validate_passes_for_an_https_initiate_login_uri()
    {
        var validator = MakeValidator();
        var client = MakeValidPublicClient() with { InitiateLoginUri = "https://app.example.com/login?source=idp" };

        var act = () => validator.Validate(client);

        act.Should().NotThrow();
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

        var act = () => validator.Validate(client);

        act.Should().Throw<ZeeKayDaConfigurationException>()
            .Which.AggregatedFailures.Should().Contain(f => f.Code == code);
    }
}
