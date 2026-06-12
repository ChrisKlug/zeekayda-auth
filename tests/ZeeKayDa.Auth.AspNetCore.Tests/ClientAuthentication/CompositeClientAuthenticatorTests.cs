using System.Text;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Primitives;
using ZeeKayDa.Auth;
using ZeeKayDa.Auth.AspNetCore.ClientAuthentication;
using ZeeKayDa.Auth.Clients;
using ZeeKayDa.Auth.Configuration;

namespace ZeeKayDa.Auth.AspNetCore.Tests.ClientAuthentication;

public sealed class CompositeClientAuthenticatorTests
{
    // ── Fake infrastructure ───────────────────────────────────────────────────────────────────────

    private sealed class FakeSecret : IClientSecret { }

    /// <summary>
    /// Trackable hasher that handles any <see cref="FakeSecret"/>.
    /// Verify result is configurable per instance or per credential identity.
    /// </summary>
    private sealed class FakeHasher : IClientSecretHasher
    {
        private readonly Func<IClientSecret, bool> _verifyResult;
        private int _callCount;

        public int CallCount => _callCount;

        public FakeHasher(bool result = false) : this(_ => result) { }
        public FakeHasher(Func<IClientSecret, bool> verifyResult) => _verifyResult = verifyResult;

        public bool CanHandle(IClientSecret secret) => secret is FakeSecret;
        public bool Verify(IClientSecret stored, ReadOnlySpan<char> presented)
        {
            Interlocked.Increment(ref _callCount);
            return _verifyResult(stored);
        }
        public IClientSecret Create(string plaintext) => new FakeSecret();
    }

    private sealed class FakeClientRepository : IClientRepository
    {
        private readonly IClientRegistration? _client;
        public FakeClientRepository(IClientRegistration? client = null) => _client = client;
        public ValueTask<IClientRegistration?> FindByClientIdAsync(string clientId, CancellationToken ct)
            => ValueTask.FromResult(_client);
    }

    private sealed class MinimalClient : IClientRegistration
    {
        public required string ClientId { get; init; }
        public required IReadOnlyList<IClientCredential> Credentials { get; init; }
        public required bool IsPublic { get; init; }
        public required IReadOnlySet<string> AllowedTokenEndpointAuthMethods { get; init; }
        public IReadOnlySet<string> RedirectUris { get; } = new HashSet<string>(StringComparer.Ordinal);
        public IReadOnlySet<string> PostLogoutRedirectUris { get; } = new HashSet<string>(StringComparer.Ordinal);
        public IReadOnlySet<string> AllowedScopes { get; } = new HashSet<string>(StringComparer.Ordinal);
        public IReadOnlySet<GrantType> AllowedGrantTypes { get; } = new HashSet<GrantType>();
        public IReadOnlySet<ResponseType> AllowedResponseTypes { get; } = new HashSet<ResponseType>();
        public IReadOnlySet<ResponseMode> AllowedResponseModes { get; } = new HashSet<ResponseMode>();
        public bool EnableZkdErrorCodes { get; }
    }

    /// <summary>
    /// A fake authenticator that always returns <see langword="true"/> from CanHandle with a
    /// fixed method string. Used to construct multi-mechanism scenarios without coupling to
    /// <see cref="ClientSecretAuthenticator"/>.
    /// </summary>
    private sealed class AlwaysHandlesAuthenticator : IClientAuthenticator
    {
        private readonly string _method;
        public AlwaysHandlesAuthenticator(string method) => _method = method;
        public IReadOnlySet<string> AuthenticationMethods =>
            new HashSet<string>(StringComparer.Ordinal) { _method };
        public bool CanHandle(TokenRequestContext context, out string? method)
        {
            method = _method;
            return true;
        }
        public ValueTask<ClientAuthenticationResult> AuthenticateAsync(
            ClientAuthenticationContext context, CancellationToken ct)
            => ValueTask.FromResult(ClientAuthenticationResult.Valid());
    }

    // ── Helpers ───────────────────────────────────────────────────────────────────────────────────

    private static (
        CompositeClientAuthenticator Composite,
        FakeHasher Hasher)
        CreateComposite(
            IClientRegistration? client,
            bool verifyResult = false,
            TokenEndpointAuthMethod[]? allowedMethods = null)
    {
        var hasher = new FakeHasher(verifyResult);
        return CreateCompositeWithHasher(client, hasher, allowedMethods);
    }

    private static (
        CompositeClientAuthenticator Composite,
        FakeHasher Hasher)
        CreateCompositeWithHasher(
            IClientRegistration? client,
            FakeHasher hasher,
            TokenEndpointAuthMethod[]? allowedMethods = null)
    {
        var compositeHasher = new CompositeClientSecretHasher(
            [hasher],
            Options.Create(new ClientSecretHasherRegistrationOptions()));

        var authenticator = new ClientSecretAuthenticator(compositeHasher);

        var serverOptions = CreateServerOptions(
            allowedMethods ?? [TokenEndpointAuthMethod.ClientSecretBasic]);

        var composite = new CompositeClientAuthenticator(
            [authenticator],
            new FakeClientRepository(client),
            serverOptions,
            compositeHasher);

        return (composite, hasher);
    }

    private static IOptions<AuthorizationServerOptions> CreateServerOptions(
        params TokenEndpointAuthMethod[] allowedMethods)
    {
        var options = new AuthorizationServerOptions();
        options.TokenEndpoint.AuthMethodsSupported =
            allowedMethods.Length > 0
                ? new List<TokenEndpointAuthMethod>(allowedMethods)
                : [TokenEndpointAuthMethod.ClientSecretBasic];
        return Options.Create(options);
    }

    private static MinimalClient CreateConfidentialClient(
        string clientId = "client-1",
        IClientSecret? secret = null,
        string allowedMethod = TokenEndpointAuthMethods.ClientSecretBasic)
    {
        IReadOnlyList<IClientCredential> creds = secret is not null
            ? new List<IClientCredential> { secret }
            : [];

        return new MinimalClient
        {
            ClientId = clientId,
            Credentials = creds,
            IsPublic = false,
            AllowedTokenEndpointAuthMethods =
                new HashSet<string>(StringComparer.Ordinal) { allowedMethod },
        };
    }

    private static MinimalClient CreatePublicClient(string clientId = "public-client")
        => new()
        {
            ClientId = clientId,
            Credentials = [],
            IsPublic = true,
            AllowedTokenEndpointAuthMethods =
                new HashSet<string>(StringComparer.Ordinal) { TokenEndpointAuthMethods.None },
        };

    private static DefaultHttpContext CreateHttpContextWithBasicAuth(string credentials, string clientId)
    {
        var ctx = new DefaultHttpContext();
        ctx.Request.Headers.Authorization =
            "Basic " + Convert.ToBase64String(Encoding.UTF8.GetBytes(credentials));
        ctx.Request.Form = new FormCollection(new Dictionary<string, StringValues>
        {
            ["client_id"] = clientId,
        });
        return ctx;
    }

    // ── AC 18: happy path ─────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task AuthenticateAsync_returns_Authenticated_true_for_valid_client_secret_basic()
    {
        var secret = new FakeSecret();
        var client = CreateConfidentialClient(secret: secret);
        var (composite, _) = CreateComposite(client, verifyResult: true);

        var httpContext = CreateHttpContextWithBasicAuth("client-1:correct-secret", "client-1");

        var result = await composite.AuthenticateAsync("client-1", httpContext, TestContext.Current.CancellationToken);

        result.Authenticated.Should().BeTrue();
    }

    // ── AC 19: wrong credential — timing padding ───────────────────────────────────────────────────

    [Fact]
    public async Task AuthenticateAsync_returns_Authenticated_false_and_pads_timing_when_credential_is_wrong()
    {
        var secret = new FakeSecret();
        var client = CreateConfidentialClient(secret: secret);
        var (composite, hasher) = CreateComposite(client, verifyResult: false);

        var httpContext = CreateHttpContextWithBasicAuth("client-1:wrong-secret", "client-1");

        var result = await composite.AuthenticateAsync("client-1", httpContext, TestContext.Current.CancellationToken);

        result.Authenticated.Should().BeFalse();
        hasher.CallCount.Should().BeGreaterThan(1,
            "PadFailureToCredentialBudget must fire after a wrong credential to pad timing");
    }

    // ── AC 20: unknown client — timing padding ────────────────────────────────────────────────────

    [Fact]
    public async Task AuthenticateAsync_returns_Authenticated_false_and_pads_timing_for_unknown_client()
    {
        var (composite, hasher) = CreateComposite(client: null, verifyResult: false);

        var httpContext = CreateHttpContextWithBasicAuth("unknown:any-secret", "unknown");

        var result = await composite.AuthenticateAsync("unknown", httpContext, TestContext.Current.CancellationToken);

        result.Authenticated.Should().BeFalse();
        hasher.CallCount.Should().Be(
            CompositeClientSecretHasher.MaxActiveSharedSecretsPerClient,
            "VerifyUnknownClientForTimingOnly must fire once per credential-budget slot");
    }

    // ── AC 21: multiple mechanisms ────────────────────────────────────────────────────────────────

    [Fact]
    public async Task AuthenticateAsync_returns_Authenticated_false_when_multiple_mechanisms_are_presented()
    {
        var secret = new FakeSecret();
        var client = CreateConfidentialClient(secret: secret);
        var hasher = new FakeHasher(true);
        var compositeHasher = new CompositeClientSecretHasher(
            [hasher],
            Options.Create(new ClientSecretHasherRegistrationOptions()));

        // Two authenticators both claiming the same request simulates multiple mechanisms.
        var composite = new CompositeClientAuthenticator(
            [
                new AlwaysHandlesAuthenticator("method_a"),
                new AlwaysHandlesAuthenticator("method_b"),
            ],
            new FakeClientRepository(client),
            CreateServerOptions(TokenEndpointAuthMethod.ClientSecretBasic),
            compositeHasher);

        var httpContext = new DefaultHttpContext();
        httpContext.Request.Form = new FormCollection(new Dictionary<string, StringValues>
        {
            ["client_id"] = "client-1",
        });

        var result = await composite.AuthenticateAsync("client-1", httpContext, TestContext.Current.CancellationToken);

        result.Authenticated.Should().BeFalse();
    }

    // ── AC 22: none fallback ──────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task AuthenticateAsync_returns_Authenticated_true_for_public_client_on_none_fallback()
    {
        var publicClient = CreatePublicClient();
        var (composite, _) = CreateCompositeWithHasher(
            publicClient,
            new FakeHasher(),
            allowedMethods: [TokenEndpointAuthMethod.ClientSecretBasic, TokenEndpointAuthMethod.None]);

        var httpContext = new DefaultHttpContext(); // no auth material
        httpContext.Request.Form = new FormCollection(new Dictionary<string, StringValues>
        {
            ["client_id"] = "public-client",
        });

        var result = await composite.AuthenticateAsync("public-client", httpContext, TestContext.Current.CancellationToken);

        result.Authenticated.Should().BeTrue();
    }

    [Fact]
    public async Task AuthenticateAsync_returns_Authenticated_false_and_pads_timing_for_confidential_client_on_none_fallback()
    {
        var secret = new FakeSecret();
        var confidentialClient = CreateConfidentialClient(secret: secret);
        var hasher = new FakeHasher();
        var (composite, _) = CreateCompositeWithHasher(
            confidentialClient,
            hasher,
            allowedMethods: [TokenEndpointAuthMethod.ClientSecretBasic, TokenEndpointAuthMethod.None]);

        var httpContext = new DefaultHttpContext(); // no auth material
        httpContext.Request.Form = new FormCollection(new Dictionary<string, StringValues>
        {
            ["client_id"] = "client-1",
        });

        var result = await composite.AuthenticateAsync("client-1", httpContext, TestContext.Current.CancellationToken);

        result.Authenticated.Should().BeFalse();
        hasher.CallCount.Should().Be(
            CompositeClientSecretHasher.MaxActiveSharedSecretsPerClient,
            "none-path rejections must be timing-padded to avoid leaking client shape");
    }

    // ── AC 23: none fallback with auth material ───────────────────────────────────────────────────

    [Fact]
    public async Task AuthenticateAsync_returns_Authenticated_false_for_public_client_that_presents_auth_material()
    {
        var publicClient = CreatePublicClient();
        var (composite, _) = CreateCompositeWithHasher(
            publicClient,
            new FakeHasher(true),
            allowedMethods: [TokenEndpointAuthMethod.ClientSecretBasic, TokenEndpointAuthMethod.None]);

        // Public client presents a Basic auth header — method is detected but per-client
        // AllowedTokenEndpointAuthMethods = { "none" } does not contain "client_secret_basic".
        var httpContext = CreateHttpContextWithBasicAuth("public-client:some-secret", "public-client");

        var result = await composite.AuthenticateAsync("public-client", httpContext, TestContext.Current.CancellationToken);

        result.Authenticated.Should().BeFalse();
    }

    // ── AC 24: credential rotation ────────────────────────────────────────────────────────────────

    [Fact]
    public async Task AuthenticateAsync_returns_Authenticated_true_when_second_credential_is_correct()
    {
        var wrongSecret = new FakeSecret();
        var correctSecret = new FakeSecret();

        // Hasher that accepts only correctSecret; uses identity to distinguish the two.
        var hasher = new FakeHasher(secret => ReferenceEquals(secret, correctSecret));
        var client = new MinimalClient
        {
            ClientId = "client-1",
            Credentials = [wrongSecret, correctSecret],
            IsPublic = false,
            AllowedTokenEndpointAuthMethods =
                new HashSet<string>(StringComparer.Ordinal) { TokenEndpointAuthMethods.ClientSecretBasic },
        };

        var (composite, _) = CreateCompositeWithHasher(client, hasher);

        var httpContext = CreateHttpContextWithBasicAuth("client-1:correct-secret", "client-1");

        var result = await composite.AuthenticateAsync("client-1", httpContext, TestContext.Current.CancellationToken);

        result.Authenticated.Should().BeTrue();
    }

    // ── AC 25: no credentials ─────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task AuthenticateAsync_returns_NotValid_and_does_not_throw_when_client_has_no_credentials()
    {
        var clientWithNoSecrets = CreateConfidentialClient(); // no secret passed → empty credentials

        var (composite, hasher) = CreateComposite(clientWithNoSecrets, verifyResult: false);

        var httpContext = CreateHttpContextWithBasicAuth("client-1:any", "client-1");

        Func<Task> act = () =>
            composite.AuthenticateAsync("client-1", httpContext, default).AsTask();

        await act.Should().NotThrowAsync("ClientSecretAuthenticator must return NotValid, never throw");

        var result = await composite.AuthenticateAsync("client-1", httpContext, TestContext.Current.CancellationToken);
        result.Authenticated.Should().BeFalse();
        hasher.CallCount.Should().BeGreaterThan(0,
            "PadFailureToCredentialBudget must fire when the credentials list is empty");
    }

    // ── Security: conflicting mechanisms → invalid_client, not none fallback ──────────────────────

    [Fact]
    public async Task AuthenticateAsync_returns_Authenticated_false_when_both_secret_mechanisms_are_presented()
    {
        // A public client presents both Basic auth AND client_secret in the body.
        // Before the HasConflictingMechanisms check: both cancel out in CanHandle → zero matches
        // → falls to none path → Valid() for a properly registered public client. This is wrong.
        var publicClient = CreatePublicClient();
        var (composite, _) = CreateCompositeWithHasher(
            publicClient,
            new FakeHasher(true),
            allowedMethods: [TokenEndpointAuthMethod.ClientSecretBasic, TokenEndpointAuthMethod.None]);

        var httpContext = new DefaultHttpContext();
        httpContext.Request.Headers.Authorization =
            "Basic " + Convert.ToBase64String(Encoding.UTF8.GetBytes("public-client:some-secret"));
        httpContext.Request.Form = new FormCollection(new Dictionary<string, StringValues>
        {
            ["client_id"] = "public-client",
            ["client_secret"] = "another-secret",
        });

        var result = await composite.AuthenticateAsync("public-client", httpContext, TestContext.Current.CancellationToken);

        result.Authenticated.Should().BeFalse(
            "simultaneous presentation of both secret mechanisms must be rejected per RFC 6749 §2.3");
    }

    // ── Security: per-client disallowed method → timing padded ───────────────────────────────────

    [Fact]
    public async Task AuthenticateAsync_returns_Authenticated_false_and_pads_timing_when_method_is_not_in_client_allowlist()
    {
        var secret = new FakeSecret();
        // Client is registered for client_secret_post only; request uses client_secret_basic.
        var client = CreateConfidentialClient(
            secret: secret,
            allowedMethod: TokenEndpointAuthMethods.ClientSecretPost);
        var hasher = new FakeHasher(false);
        var (composite, _) = CreateCompositeWithHasher(
            client,
            hasher,
            allowedMethods: [TokenEndpointAuthMethod.ClientSecretBasic, TokenEndpointAuthMethod.ClientSecretPost]);

        var httpContext = CreateHttpContextWithBasicAuth("client-1:any-secret", "client-1");

        var result = await composite.AuthenticateAsync("client-1", httpContext, TestContext.Current.CancellationToken);

        result.Authenticated.Should().BeFalse();
        hasher.CallCount.Should().Be(
            CompositeClientSecretHasher.MaxActiveSharedSecretsPerClient,
            "timing must be padded when a known client's per-client allowlist rejects the method");
    }

    // ── Security: Basic username mismatch → invalid_client ───────────────────────────────────────

    [Fact]
    public async Task AuthenticateAsync_returns_Authenticated_false_when_Basic_username_does_not_match_client_id()
    {
        var secret = new FakeSecret();
        var client = CreateConfidentialClient("client-1", secret: secret);
        // Hasher always accepts — so any success would come from bypassing the username check.
        var (composite, _) = CreateComposite(client, verifyResult: true);

        // Basic header claims "attacker" but client_id in form is "client-1".
        var httpContext = new DefaultHttpContext();
        httpContext.Request.Headers.Authorization =
            "Basic " + Convert.ToBase64String(Encoding.UTF8.GetBytes("attacker:correct-secret"));
        httpContext.Request.Form = new FormCollection(new Dictionary<string, StringValues>
        {
            ["client_id"] = "client-1",
        });

        var result = await composite.AuthenticateAsync("client-1", httpContext, TestContext.Current.CancellationToken);

        result.Authenticated.Should().BeFalse(
            "RFC 6749 §2.3.1: the Basic auth username must equal the client_id");
    }

    // ── Security: multiple Authorization headers ──────────────────────────────────────────────────

    [Fact]
    public async Task AuthenticateAsync_returns_Authenticated_false_when_multiple_Authorization_headers_are_present()
    {
        var secret = new FakeSecret();
        var client = CreateConfidentialClient(secret: secret);
        var (composite, _) = CreateComposite(client, verifyResult: true);

        var httpContext = new DefaultHttpContext();
        httpContext.Request.Headers.Authorization = new StringValues(
        [
            "Basic " + Convert.ToBase64String(Encoding.UTF8.GetBytes("client-1:secret-a")),
            "Basic " + Convert.ToBase64String(Encoding.UTF8.GetBytes("client-1:secret-b")),
        ]);
        httpContext.Request.Form = new FormCollection(new Dictionary<string, StringValues>
        {
            ["client_id"] = "client-1",
        });

        var result = await composite.AuthenticateAsync("client-1", httpContext, TestContext.Current.CancellationToken);

        result.Authenticated.Should().BeFalse(
            "multiple Authorization headers are ambiguous and must be rejected");
    }

    // ── RFC 6749 §2.3.1: percent-encoded Basic credentials ───────────────────────────────────────

    [Fact]
    public async Task AuthenticateAsync_returns_Authenticated_true_when_Basic_credentials_are_percent_encoded()
    {
        var secret = new FakeSecret();
        // client_id contains a slash and secret contains @; both must be percent-encoded in Basic.
        var client = new MinimalClient
        {
            ClientId = "client/one",
            Credentials = [secret],
            IsPublic = false,
            AllowedTokenEndpointAuthMethods =
                new HashSet<string>(StringComparer.Ordinal) { TokenEndpointAuthMethods.ClientSecretBasic },
        };
        var (composite, _) = CreateCompositeWithHasher(client, new FakeHasher(true));

        // "client%2Fone:pass%40word" decodes to "client/one:pass@word"
        var httpContext = new DefaultHttpContext();
        httpContext.Request.Headers.Authorization =
            "Basic " + Convert.ToBase64String(Encoding.UTF8.GetBytes("client%2Fone:pass%40word"));
        httpContext.Request.Form = new FormCollection(new Dictionary<string, StringValues>
        {
            ["client_id"] = "client/one",
        });

        var result = await composite.AuthenticateAsync("client/one", httpContext, TestContext.Current.CancellationToken);

        result.Authenticated.Should().BeTrue(
            "percent-encoded Basic credentials must be URL-decoded per RFC 6749 §2.3.1");
    }

    // ── client_secret_post ────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task AuthenticateAsync_returns_Authenticated_true_for_valid_client_secret_post()
    {
        var secret = new FakeSecret();
        var client = CreateConfidentialClient(
            secret: secret,
            allowedMethod: TokenEndpointAuthMethods.ClientSecretPost);
        var (composite, _) = CreateCompositeWithHasher(
            client,
            new FakeHasher(true),
            allowedMethods: [TokenEndpointAuthMethod.ClientSecretPost]);

        var httpContext = new DefaultHttpContext();
        httpContext.Request.Form = new FormCollection(new Dictionary<string, StringValues>
        {
            ["client_id"] = "client-1",
            ["client_secret"] = "correct-secret",
        });

        var result = await composite.AuthenticateAsync("client-1", httpContext, TestContext.Current.CancellationToken);

        result.Authenticated.Should().BeTrue();
    }

    [Fact]
    public async Task AuthenticateAsync_returns_Authenticated_false_and_pads_timing_for_wrong_client_secret_post_credential()
    {
        var secret = new FakeSecret();
        var client = CreateConfidentialClient(
            secret: secret,
            allowedMethod: TokenEndpointAuthMethods.ClientSecretPost);
        var (composite, hasher) = CreateCompositeWithHasher(
            client,
            new FakeHasher(false),
            allowedMethods: [TokenEndpointAuthMethod.ClientSecretPost]);

        var httpContext = new DefaultHttpContext();
        httpContext.Request.Form = new FormCollection(new Dictionary<string, StringValues>
        {
            ["client_id"] = "client-1",
            ["client_secret"] = "wrong-secret",
        });

        var result = await composite.AuthenticateAsync("client-1", httpContext, TestContext.Current.CancellationToken);

        result.Authenticated.Should().BeFalse();
        hasher.CallCount.Should().BeGreaterThan(1,
            "PadFailureToCredentialBudget must fire after a wrong client_secret_post credential");
    }

    // ── Malformed Basic credentials ───────────────────────────────────────────────────────────────

    [Fact]
    public async Task AuthenticateAsync_returns_Authenticated_false_when_Basic_header_contains_invalid_base64()
    {
        var secret = new FakeSecret();
        var client = CreateConfidentialClient(secret: secret);
        var (composite, _) = CreateComposite(client, verifyResult: true);

        var httpContext = new DefaultHttpContext();
        httpContext.Request.Headers.Authorization = "Basic not-valid-base64!!!";
        httpContext.Request.Form = new FormCollection(new Dictionary<string, StringValues>
        {
            ["client_id"] = "client-1",
        });

        var result = await composite.AuthenticateAsync("client-1", httpContext, TestContext.Current.CancellationToken);

        result.Authenticated.Should().BeFalse(
            "a Basic header with invalid base64 must be rejected");
    }

    [Fact]
    public async Task AuthenticateAsync_returns_Authenticated_false_when_Basic_header_contains_no_colon_separator()
    {
        var secret = new FakeSecret();
        var client = CreateConfidentialClient(secret: secret);
        var (composite, _) = CreateComposite(client, verifyResult: true);

        var httpContext = new DefaultHttpContext();
        // Valid base64 but decodes to a string with no colon — no username:password separator.
        httpContext.Request.Headers.Authorization =
            "Basic " + Convert.ToBase64String(Encoding.UTF8.GetBytes("nocredentialseparator"));
        httpContext.Request.Form = new FormCollection(new Dictionary<string, StringValues>
        {
            ["client_id"] = "client-1",
        });

        var result = await composite.AuthenticateAsync("client-1", httpContext, TestContext.Current.CancellationToken);

        result.Authenticated.Should().BeFalse(
            "a Basic header with no colon separator must be rejected");
    }
}
