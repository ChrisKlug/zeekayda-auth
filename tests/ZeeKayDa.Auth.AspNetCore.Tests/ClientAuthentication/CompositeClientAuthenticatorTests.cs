using System.Text;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Primitives;
using ZeeKayDa.Auth;
using ZeeKayDa.Auth.AspNetCore.ClientAuthentication;
using ZeeKayDa.Auth.Authorization;
using ZeeKayDa.Auth.Clients;
using ZeeKayDa.Auth.Configuration;
using ZeeKayDa.Auth.Logging;
using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.AspNetCore.Tests.ClientAuthentication;

public sealed class CompositeClientAuthenticatorTests
{
    // ── Fake infrastructure ───────────────────────────────────────────────────────────────────────

    private static ClientSecret FakeSecret(string name = "x") => new($"$fake-secret${name}");

    /// <summary>
    /// Trackable hasher that owns the <c>fake-secret</c> id.
    /// Verify result is configurable per instance or per credential.
    /// </summary>
    private sealed class FakeHasher : IClientSecretHasher
    {
        private readonly Func<ClientSecret, bool> _verifyResult;
        private int _callCount;
        private int _derivationCount;

        public int CallCount => _callCount;

        /// <summary>
        /// Verifications that would do real work: the built-in PBKDF2 hasher returns without
        /// deriving for an empty presented value, so those are not counted here.
        /// </summary>
        public int DerivationCount => _derivationCount;

        public FakeHasher(bool result = false) : this(_ => result) { }
        public FakeHasher(Func<ClientSecret, bool> verifyResult) => _verifyResult = verifyResult;

        public IReadOnlySet<string> AlgorithmIds { get; } = new HashSet<string> { "fake-secret" };
        public bool Verify(ReadOnlySpan<char> presented, ClientSecret stored)
        {
            Interlocked.Increment(ref _callCount);
            if (!presented.IsEmpty)
                Interlocked.Increment(ref _derivationCount);
            return _verifyResult(stored);
        }
        public ClientSecret Create(ReadOnlySpan<char> plaintext) => FakeSecret();
    }

    private sealed class PassingRegistrationValidator : IClientRegistrationValidator
    {
        // Deliberately accepts everything: these tests exercise the composite's dispatch
        // rules with minimal fake registrations, not registration validation, which has its
        // own suites (ClientRegistrationValidatorTests, ValidatedClientResolverTests).
        public IReadOnlyList<ZeeKayDaConfigurationFailure> Validate(IClientWithCredentials client) => [];
    }

    private static ValidatedClientResolver Resolver(IClientWithCredentials? client) => new(
        new FakeClientRepository(client),
        new PassingRegistrationValidator(),
        NullSanitizingLogger<ValidatedClientResolver>.Instance);

    private sealed class FakeClientRepository : IClientRepository
    {
        private readonly IClientWithCredentials? _client;
        public FakeClientRepository(IClientWithCredentials? client = null) => _client = client;
        public Task<IClientWithCredentials?> FindByClientIdAsync(string clientId, CancellationToken ct)
            => Task.FromResult(_client);
    }

    /// <summary>
    /// A set whose <see cref="Count"/> disagrees with what it enumerates, as a custom registration's
    /// collection type is free to do.
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

    private sealed class MinimalClient : IClientWithCredentials
    {
        public required string ClientId { get; init; }
        public required IReadOnlyList<ClientSecret> Secrets { get; init; }
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
        public Task<ClientAuthenticationResult> AuthenticateAsync(
            ClientAuthenticationContext context, CancellationToken ct)
            => Task.FromResult(ClientAuthenticationResult.Valid());
    }

    /// <summary>
    /// A third-party authenticator for a method of its own, refusing however <paramref name="authenticate"/>
    /// says: cheaply, or through <see cref="ClientSecrets.Verify"/>.
    /// </summary>
    private sealed class CustomAuthenticator(
        Func<ClientAuthenticationContext, ClientAuthenticationResult> authenticate) : IClientAuthenticator
    {
        public const string Method = "private_key_jwt";

        public IReadOnlySet<string> AuthenticationMethods { get; } =
            new HashSet<string>(StringComparer.Ordinal) { Method };

        public bool CanHandle(TokenRequestContext context, out string? method)
        {
            method = Method;
            return true;
        }

        public Task<ClientAuthenticationResult> AuthenticateAsync(
            ClientAuthenticationContext context, CancellationToken ct)
            => Task.FromResult(authenticate(context));
    }

    private static async Task<int> HasherCallsToRefuse(
        IClientWithCredentials? client,
        Func<ClientSecrets, Func<ClientAuthenticationContext, ClientAuthenticationResult>> authenticate)
    {
        var hasher = new FakeHasher(false);
        var secrets = new ClientSecrets(Registry([hasher]), NullSanitizingLogger<ClientSecrets>.Instance);
        var composite = new CompositeClientAuthenticator(
            [new CustomAuthenticator(authenticate(secrets))],
            Resolver(client),
            CreateServerOptions(CustomAuthenticator.Method),
            secrets,
            NullSanitizingLogger<CompositeClientAuthenticator>.Instance);

        var result = await composite.AuthenticateAsync(
            "client-1", new DefaultHttpContext(), TestContext.Current.CancellationToken);

        result.Authenticated.Should().BeFalse();
        return hasher.CallCount;
    }

    /// <summary>A caller-supplied authenticator that returns null despite its non-null contract.</summary>
    private sealed class NullReturningAuthenticator : IClientAuthenticator
    {
        public IReadOnlySet<string> AuthenticationMethods =>
            new HashSet<string>(StringComparer.Ordinal) { TokenEndpointAuthMethods.ClientSecretBasic };

        public bool CanHandle(TokenRequestContext context, out string? method)
        {
            method = TokenEndpointAuthMethods.ClientSecretBasic;
            return true;
        }

        public Task<ClientAuthenticationResult> AuthenticateAsync(
            ClientAuthenticationContext context, CancellationToken ct)
            => Task.FromResult<ClientAuthenticationResult>(null!);
    }

    private sealed class ThrowingCanHandleAuthenticator : IClientAuthenticator
    {
        public IReadOnlySet<string> AuthenticationMethods =>
            new HashSet<string>(StringComparer.Ordinal) { "throwing_method" };

        public bool CanHandle(TokenRequestContext context, out string? method)
            => throw new InvalidOperationException("Simulated authenticator bug");

        public Task<ClientAuthenticationResult> AuthenticateAsync(
            ClientAuthenticationContext context, CancellationToken ct)
            => throw new NotSupportedException("Should not be reached");
    }

    /// <summary>
    /// Authenticator whose <see cref="CanHandle"/> returns a method string that is NOT present in
    /// its own <see cref="AuthenticationMethods"/> set, simulating a buggy authenticator.
    /// </summary>
    private sealed class MismatchedMethodAuthenticator : IClientAuthenticator
    {
        private readonly string _declared;
        private readonly string _returned;

        public MismatchedMethodAuthenticator(string declared, string returned)
        {
            _declared = declared;
            _returned = returned;
        }

        public IReadOnlySet<string> AuthenticationMethods =>
            new HashSet<string>(StringComparer.Ordinal) { _declared };

        public bool CanHandle(TokenRequestContext context, out string? method)
        {
            method = _returned;
            return true;
        }

        public Task<ClientAuthenticationResult> AuthenticateAsync(
            ClientAuthenticationContext context, CancellationToken ct)
            => throw new NotSupportedException("Should not be reached");
    }

    // ── Helpers ───────────────────────────────────────────────────────────────────────────────────

    private static (
        CompositeClientAuthenticator Composite,
        FakeHasher Hasher)
        CreateComposite(
            IClientWithCredentials? client,
            bool verifyResult = false,
            string[]? allowedMethods = null)
    {
        var hasher = new FakeHasher(verifyResult);
        return CreateCompositeWithHasher(client, hasher, allowedMethods);
    }

    private static ClientSecretHasherRegistry Registry(IEnumerable<IClientSecretHasher> hashers) =>
        new(hashers, Options.Create(new ClientSecretHasherRegistrationOptions()));

    private static (
        CompositeClientAuthenticator Composite,
        FakeHasher Hasher)
        CreateCompositeWithHasher(
            IClientWithCredentials? client,
            FakeHasher hasher,
            string[]? allowedMethods = null)
    {
        var registry = Registry([hasher]);
        var secrets = new ClientSecrets(registry, NullSanitizingLogger<ClientSecrets>.Instance);

        var authenticator = new ClientSecretAuthenticator(secrets);

        var serverOptions = CreateServerOptions(
            allowedMethods ?? [TokenEndpointAuthMethods.ClientSecretBasic]);

        var composite = new CompositeClientAuthenticator(
            [authenticator],
            Resolver(client),
            serverOptions,
            secrets,
            NullSanitizingLogger<CompositeClientAuthenticator>.Instance);

        return (composite, hasher);
    }

    /// <summary>
    /// A composite whose resolver runs the real registration validator. The <c>none</c> path trusts
    /// <see cref="IClient.IsPublic"/> because the resolver guarantees public ⇔ no credentials
    /// ⇔ methods exactly <c>{ "none" }</c>; these tests prove that guarantee end to end.
    /// </summary>
    private static (CompositeClientAuthenticator Composite, CapturingSanitizingLogger<ValidatedClientResolver> ResolverLogger)
        CreateValidatingComposite(IClientWithCredentials client, FakeHasher hasher)
    {
        var registry = Registry([hasher]);
        var secrets = new ClientSecrets(registry, NullSanitizingLogger<ClientSecrets>.Instance);
        var serverOptions = CreateServerOptions(
            TokenEndpointAuthMethods.ClientSecretBasic, TokenEndpointAuthMethods.None);
        serverOptions.Value.Issuer = "https://auth.example.com";
        var resolverLogger = new CapturingSanitizingLogger<ValidatedClientResolver>();
        var resolver = new ValidatedClientResolver(
            new FakeClientRepository(client),
            new ClientRegistrationValidator(
                serverOptions,
                registry,
                NullSanitizingLogger<ClientRegistrationValidator>.Instance,
                keyRing: null),
            resolverLogger);
        var composite = new CompositeClientAuthenticator(
            [new ClientSecretAuthenticator(secrets)],
            resolver,
            serverOptions,
            secrets,
            NullSanitizingLogger<CompositeClientAuthenticator>.Instance);
        return (composite, resolverLogger);
    }

    private const string TrinityViolation = "inconsistent public/confidential configuration";

    private static IOptions<AuthorizationServerOptions> CreateServerOptions(
        params string[] allowedMethods)
    {
        var options = new AuthorizationServerOptions();
        options.TokenEndpoint.AuthMethodsSupported =
            allowedMethods.Length > 0
                ? [.. allowedMethods]
                : [TokenEndpointAuthMethods.ClientSecretBasic];
        return Options.Create(options);
    }

    private static MinimalClient CreateConfidentialClient(
        string clientId = "client-1",
        ClientSecret? secret = null,
        string allowedMethod = TokenEndpointAuthMethods.ClientSecretBasic)
    {
        IReadOnlyList<ClientSecret> creds = secret is not null
            ? new List<ClientSecret> { secret }
            : [];

        return new MinimalClient
        {
            ClientId = clientId,
            Secrets = creds,
            IsPublic = false,
            AllowedTokenEndpointAuthMethods =
                new HashSet<string>(StringComparer.Ordinal) { allowedMethod },
        };
    }

    private static MinimalClient CreatePublicClient(string clientId = "public-client")
        => new()
        {
            ClientId = clientId,
            Secrets = [],
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
        var secret = FakeSecret();
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
        var secret = FakeSecret();
        var client = CreateConfidentialClient(secret: secret);
        var (composite, hasher) = CreateComposite(client, verifyResult: false);

        var httpContext = CreateHttpContextWithBasicAuth("client-1:wrong-secret", "client-1");

        var result = await composite.AuthenticateAsync("client-1", httpContext, TestContext.Current.CancellationToken);

        result.Authenticated.Should().BeFalse();
        hasher.CallCount.Should().Be(ClientSecrets.MaxActiveSecretsPerClient,
            "a wrong credential is padded to the failure budget");
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
            ClientSecrets.MaxActiveSecretsPerClient,
            "an unknown client is padded once per credential-budget slot");
    }

    [Fact]
    public async Task A_custom_authenticator_refusing_without_verifying_is_padded_like_an_unknown_client()
    {
        var knownClient = CreateConfidentialClient(secret: FakeSecret(), allowedMethod: CustomAuthenticator.Method);

        var known = await HasherCallsToRefuse(knownClient, _ => _ => ClientAuthenticationResult.NotValid());
        var unknown = await HasherCallsToRefuse(client: null, _ => _ => ClientAuthenticationResult.NotValid());

        known.Should().Be(ClientSecrets.MaxActiveSecretsPerClient);
        known.Should().Be(unknown, "a refusal that checked no secret is padded by the composite");
    }

    [Fact]
    public async Task A_refusal_from_a_failed_verification_is_not_padded_again()
    {
        var knownClient = CreateConfidentialClient(secret: FakeSecret(), allowedMethod: CustomAuthenticator.Method);

        var calls = await HasherCallsToRefuse(knownClient, secrets => context =>
            ClientAuthenticationResult.From(secrets.Verify("wrong", context.Client.Secrets)));

        calls.Should().Be(
            ClientSecrets.MaxActiveSecretsPerClient,
            "Verify already spent the failure budget; padding again would make a known client slower than an unknown one");
    }

    [Fact]
    public async Task A_failed_verification_kept_from_an_earlier_request_does_not_excuse_a_later_refusal_from_padding()
    {
        var knownClient = CreateConfidentialClient(secret: FakeSecret(), allowedMethod: CustomAuthenticator.Method);
        SecretVerification? kept = null;

        var calls = await HasherCallsToRefuse(knownClient, secrets => context =>
        {
            kept ??= secrets.Verify("wrong", context.Client.Secrets);
            return ClientAuthenticationResult.From(kept);
        });
        var replayedCalls = await HasherCallsToRefuse(knownClient, _ => _ => ClientAuthenticationResult.From(kept!));

        calls.Should().Be(ClientSecrets.MaxActiveSecretsPerClient);
        replayedCalls.Should().Be(
            ClientSecrets.MaxActiveSecretsPerClient,
            "a failure vouches for its padding once; replayed, it checked no secret and is padded");
    }

    [Fact]
    public async Task A_failed_result_returned_again_is_padded_like_any_other_refusal()
    {
        var knownClient = CreateConfidentialClient(secret: FakeSecret(), allowedMethod: CustomAuthenticator.Method);
        ClientAuthenticationResult? kept = null;

        var calls = await HasherCallsToRefuse(knownClient, secrets => context =>
            kept ??= ClientAuthenticationResult.From(secrets.Verify("wrong", context.Client.Secrets)));
        var replayedCalls = await HasherCallsToRefuse(knownClient, _ => _ => kept!);

        calls.Should().Be(ClientSecrets.MaxActiveSecretsPerClient);
        replayedCalls.Should().Be(ClientSecrets.MaxActiveSecretsPerClient, "a result vouches for its padding once");
    }

    [Fact]
    public async Task Building_a_result_twice_from_one_failed_verification_does_not_pad_twice()
    {
        var knownClient = CreateConfidentialClient(secret: FakeSecret(), allowedMethod: CustomAuthenticator.Method);

        var calls = await HasherCallsToRefuse(knownClient, secrets => context =>
        {
            var verification = secrets.Verify("wrong", context.Client.Secrets);
            _ = ClientAuthenticationResult.From(verification);
            return ClientAuthenticationResult.From(verification);
        });

        calls.Should().Be(ClientSecrets.MaxActiveSecretsPerClient, "padding is claimed when the result is used, not built");
    }

    // ── AC 21: multiple mechanisms ────────────────────────────────────────────────────────────────

    [Fact]
    public async Task An_authenticator_returning_null_is_a_refusal_not_a_fault()
    {
        var client = CreateConfidentialClient(secret: FakeSecret());
        var hasher = new FakeHasher(true);
        var registry = Registry([hasher]);
        var secrets = new ClientSecrets(registry, NullSanitizingLogger<ClientSecrets>.Instance);
        var composite = new CompositeClientAuthenticator(
            [new NullReturningAuthenticator()],
            Resolver(client),
            CreateServerOptions(TokenEndpointAuthMethods.ClientSecretBasic),
            secrets,
            NullSanitizingLogger<CompositeClientAuthenticator>.Instance);
        var httpContext = new DefaultHttpContext();
        httpContext.Request.Form = new FormCollection(new Dictionary<string, StringValues>
        {
            ["client_id"] = "client-1",
        });

        var result = await composite.AuthenticateAsync("client-1", httpContext, TestContext.Current.CancellationToken);

        result.Authenticated.Should().BeFalse("an extension point returning null must fail closed, never throw");
        result.Client.Should().BeNull();
        hasher.CallCount.Should().Be(ClientSecrets.MaxActiveSecretsPerClient, "a null checked no secret, so it is padded");
    }

    [Fact]
    public async Task AuthenticateAsync_returns_Authenticated_false_when_multiple_mechanisms_are_presented()
    {
        var secret = FakeSecret();
        var client = CreateConfidentialClient(secret: secret);
        var hasher = new FakeHasher(true);
        var registry = Registry([hasher]);
        var secrets = new ClientSecrets(registry, NullSanitizingLogger<ClientSecrets>.Instance);

        // Two authenticators both claiming the same request simulates multiple mechanisms.
        var composite = new CompositeClientAuthenticator(
            [
                new AlwaysHandlesAuthenticator("method_a"),
                new AlwaysHandlesAuthenticator("method_b"),
            ],
            Resolver(client),
            CreateServerOptions(TokenEndpointAuthMethods.ClientSecretBasic),
            secrets,
            NullSanitizingLogger<CompositeClientAuthenticator>.Instance);

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
            allowedMethods: [TokenEndpointAuthMethods.ClientSecretBasic, TokenEndpointAuthMethods.None]);

        var httpContext = new DefaultHttpContext(); // no auth material
        httpContext.Request.Form = new FormCollection(new Dictionary<string, StringValues>
        {
            ["client_id"] = "public-client",
        });

        var result = await composite.AuthenticateAsync("public-client", httpContext, TestContext.Current.CancellationToken);

        result.Authenticated.Should().BeTrue();
    }

    [Fact]
    public async Task AuthenticateAsync_refuses_none_fallback_when_client_auth_methods_set_reports_one_entry_but_yields_more()
    {
        var hasher = new FakeHasher();
        var miscountingClient = new MinimalClient
        {
            ClientId = "public-client",
            Secrets = [],
            IsPublic = true,
            AllowedTokenEndpointAuthMethods = new MiscountingSet(
                [TokenEndpointAuthMethods.None, TokenEndpointAuthMethods.ClientSecretBasic],
                reportedCount: 1),
        };
        var (composite, resolverLogger) = CreateValidatingComposite(miscountingClient, hasher);

        var httpContext = new DefaultHttpContext(); // no auth material
        httpContext.Request.Form = new FormCollection(new Dictionary<string, StringValues>
        {
            ["client_id"] = "public-client",
        });

        var result = await composite.AuthenticateAsync("public-client", httpContext, TestContext.Current.CancellationToken);

        result.Authenticated.Should().BeFalse();
        hasher.CallCount.Should().Be(ClientSecrets.MaxActiveSecretsPerClient);
        resolverLogger.Entries.Should().ContainSingle(e => e.Message.Contains(TrinityViolation));
    }

    [Fact]
    public async Task AuthenticateAsync_returns_Authenticated_false_and_pads_timing_for_confidential_client_on_none_fallback()
    {
        var secret = FakeSecret();
        var confidentialClient = CreateConfidentialClient(secret: secret);
        var hasher = new FakeHasher();
        var (composite, _) = CreateCompositeWithHasher(
            confidentialClient,
            hasher,
            allowedMethods: [TokenEndpointAuthMethods.ClientSecretBasic, TokenEndpointAuthMethods.None]);

        var httpContext = new DefaultHttpContext(); // no auth material
        httpContext.Request.Form = new FormCollection(new Dictionary<string, StringValues>
        {
            ["client_id"] = "client-1",
        });

        var result = await composite.AuthenticateAsync("client-1", httpContext, TestContext.Current.CancellationToken);

        result.Authenticated.Should().BeFalse();
        hasher.CallCount.Should().Be(
            ClientSecrets.MaxActiveSecretsPerClient,
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
            allowedMethods: [TokenEndpointAuthMethods.ClientSecretBasic, TokenEndpointAuthMethods.None]);

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
        var wrongSecret = FakeSecret("wrong");
        var correctSecret = FakeSecret("correct");

        // Hasher that accepts only correctSecret. It matches by name, not by reference: the client is
        // served as a snapshot, so the hasher is handed a copy of each credential, never the original.
        var hasher = new FakeHasher(secret => secret == FakeSecret("correct"));
        var client = new MinimalClient
        {
            ClientId = "client-1",
            Secrets = [wrongSecret, correctSecret],
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

        var act = () =>
            composite.AuthenticateAsync("client-1", httpContext, TestContext.Current.CancellationToken).AsTask();

        var result = (await act.Should().NotThrowAsync("ClientSecretAuthenticator must return NotValid, never throw")).Which;
        result.Authenticated.Should().BeFalse();
        hasher.CallCount.Should().Be(ClientSecrets.MaxActiveSecretsPerClient,
            "a client with no credentials is padded to the failure budget");
    }

    // ── Security: conflicting mechanisms → invalid_client, not none fallback ──────────────────────

    [Fact]
    public async Task AuthenticateAsync_returns_Authenticated_false_when_both_secret_mechanisms_are_presented_by_public_client()
    {
        // A public client presents both Basic auth AND client_secret in the body.
        // CanHandle returns (true, client_secret_basic) so the request doesn't fall to the 'none'
        // fallback; the per-client method check then rejects it (public client only allows "none").
        var publicClient = CreatePublicClient();
        var (composite, _) = CreateCompositeWithHasher(
            publicClient,
            new FakeHasher(true),
            allowedMethods: [TokenEndpointAuthMethods.ClientSecretBasic, TokenEndpointAuthMethods.None]);

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

    [Fact]
    public async Task AuthenticateAsync_returns_Authenticated_false_when_both_secret_mechanisms_are_presented_by_confidential_client()
    {
        // A confidential client presents both Basic auth AND client_secret in the body.
        // ClientSecretAuthenticator.AuthenticateAsync detects the conflict and rejects
        // even though the credentials themselves would be valid (FakeHasher returns true).
        var secret = FakeSecret();
        var client = CreateConfidentialClient(secret: secret);
        var (composite, hasher) = CreateCompositeWithHasher(
            client,
            new FakeHasher(true),
            allowedMethods: [TokenEndpointAuthMethods.ClientSecretBasic]);

        var httpContext = new DefaultHttpContext();
        httpContext.Request.Headers.Authorization =
            "Basic " + Convert.ToBase64String(Encoding.UTF8.GetBytes("client-1:some-secret"));
        httpContext.Request.Form = new FormCollection(new Dictionary<string, StringValues>
        {
            ["client_id"] = "client-1",
            ["client_secret"] = "another-secret",
        });

        var result = await composite.AuthenticateAsync("client-1", httpContext, TestContext.Current.CancellationToken);

        result.Authenticated.Should().BeFalse(
            "simultaneous presentation of both secret mechanisms must be rejected per RFC 6749 §2.3");
        hasher.CallCount.Should().Be(
            ClientSecrets.MaxActiveSecretsPerClient, "a malformed request is padded like a wrong secret");
    }

    // ── Security: per-client disallowed method → timing padded ───────────────────────────────────

    [Fact]
    public async Task AuthenticateAsync_returns_Authenticated_false_and_pads_timing_when_method_is_not_in_client_allowlist()
    {
        var secret = FakeSecret();
        // Client is registered for client_secret_post only; request uses client_secret_basic.
        var client = CreateConfidentialClient(
            secret: secret,
            allowedMethod: TokenEndpointAuthMethods.ClientSecretPost);
        var hasher = new FakeHasher(false);
        var (composite, _) = CreateCompositeWithHasher(
            client,
            hasher,
            allowedMethods: [TokenEndpointAuthMethods.ClientSecretBasic, TokenEndpointAuthMethods.ClientSecretPost]);

        var httpContext = CreateHttpContextWithBasicAuth("client-1:any-secret", "client-1");

        var result = await composite.AuthenticateAsync("client-1", httpContext, TestContext.Current.CancellationToken);

        result.Authenticated.Should().BeFalse();
        hasher.CallCount.Should().Be(
            ClientSecrets.MaxActiveSecretsPerClient,
            "timing must be padded when a known client's per-client allowlist rejects the method");
    }

    // ── Security: Basic username mismatch → invalid_client ───────────────────────────────────────

    [Fact]
    public async Task AuthenticateAsync_returns_Authenticated_false_when_Basic_username_does_not_match_client_id()
    {
        var secret = FakeSecret();
        var client = CreateConfidentialClient("client-1", secret: secret);
        // Hasher always accepts — so any success would come from bypassing the username check.
        var (composite, hasher) = CreateComposite(client, verifyResult: true);

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
        hasher.CallCount.Should().Be(
            ClientSecrets.MaxActiveSecretsPerClient, "a malformed request is padded like a wrong secret");
    }

    [Fact]
    public async Task AuthenticateAsync_returns_Authenticated_false_when_form_client_id_disagrees_with_Basic_username()
    {
        var secret = FakeSecret();
        var client = CreateConfidentialClient("client-1", secret: secret);
        // Hasher always accepts — success would mean the consistency check was bypassed.
        var (composite, hasher) = CreateComposite(client, verifyResult: true);

        // Basic header username is "client-1" (matches what composite received), but the form
        // carries a different client_id. RFC 6749 §2.3.1: conflicting client_id values must be rejected.
        var httpContext = new DefaultHttpContext();
        httpContext.Request.Headers.Authorization =
            "Basic " + Convert.ToBase64String(Encoding.UTF8.GetBytes("client-1:correct-secret"));
        httpContext.Request.Form = new FormCollection(new Dictionary<string, StringValues>
        {
            ["client_id"] = "other-client",
        });

        var result = await composite.AuthenticateAsync("client-1", httpContext, TestContext.Current.CancellationToken);

        result.Authenticated.Should().BeFalse(
            "RFC 6749 §2.3.1: a form client_id that disagrees with the Basic-auth username must be rejected");
        hasher.CallCount.Should().Be(
            ClientSecrets.MaxActiveSecretsPerClient, "a malformed request is padded like a wrong secret");
    }

    // ── Security: multiple Authorization headers ──────────────────────────────────────────────────

    [Fact]
    public async Task AuthenticateAsync_returns_Authenticated_false_when_multiple_Authorization_headers_are_present()
    {
        var secret = FakeSecret();
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
        var secret = FakeSecret();
        // The secret contains @, which Basic percent-encodes; the client_id is encoded needlessly,
        // which a decoder must accept all the same. A client_id needing encoding is malformed.
        var client = new MinimalClient
        {
            ClientId = "client-one",
            Secrets = [secret],
            IsPublic = false,
            AllowedTokenEndpointAuthMethods =
                new HashSet<string>(StringComparer.Ordinal) { TokenEndpointAuthMethods.ClientSecretBasic },
        };
        var (composite, _) = CreateCompositeWithHasher(client, new FakeHasher(true));

        // "client%2Done:pass%40word" decodes to "client-one:pass@word"
        var httpContext = new DefaultHttpContext();
        httpContext.Request.Headers.Authorization =
            "Basic " + Convert.ToBase64String(Encoding.UTF8.GetBytes("client%2Done:pass%40word"));
        httpContext.Request.Form = new FormCollection(new Dictionary<string, StringValues>
        {
            ["client_id"] = "client-one",
        });

        var result = await composite.AuthenticateAsync("client-one", httpContext, TestContext.Current.CancellationToken);

        result.Authenticated.Should().BeTrue(
            "percent-encoded Basic credentials must be URL-decoded per RFC 6749 §2.3.1");
    }

    // ── client_secret_post ────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task AuthenticateAsync_returns_Authenticated_true_for_valid_client_secret_post()
    {
        var secret = FakeSecret();
        var client = CreateConfidentialClient(
            secret: secret,
            allowedMethod: TokenEndpointAuthMethods.ClientSecretPost);
        var (composite, _) = CreateCompositeWithHasher(
            client,
            new FakeHasher(true),
            allowedMethods: [TokenEndpointAuthMethods.ClientSecretPost]);

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
        var secret = FakeSecret();
        var client = CreateConfidentialClient(
            secret: secret,
            allowedMethod: TokenEndpointAuthMethods.ClientSecretPost);
        var (composite, hasher) = CreateCompositeWithHasher(
            client,
            new FakeHasher(false),
            allowedMethods: [TokenEndpointAuthMethods.ClientSecretPost]);

        var httpContext = new DefaultHttpContext();
        httpContext.Request.Form = new FormCollection(new Dictionary<string, StringValues>
        {
            ["client_id"] = "client-1",
            ["client_secret"] = "wrong-secret",
        });

        var result = await composite.AuthenticateAsync("client-1", httpContext, TestContext.Current.CancellationToken);

        result.Authenticated.Should().BeFalse();
        hasher.CallCount.Should().Be(ClientSecrets.MaxActiveSecretsPerClient,
            "a wrong client_secret_post credential is padded to the failure budget");
    }

    [Fact]
    public async Task AuthenticateAsync_returns_Authenticated_false_when_client_secret_post_value_is_empty()
    {
        // client_secret= (empty value): ContainsKey is true, so CanHandle returns (true, client_secret_post).
        // AuthenticateAsync enters the post path and pads from zero — not the none fallback.
        var secret = FakeSecret();
        var client = CreateConfidentialClient(
            secret: secret,
            allowedMethod: TokenEndpointAuthMethods.ClientSecretPost);
        var (composite, hasher) = CreateCompositeWithHasher(
            client,
            new FakeHasher(false),
            allowedMethods: [TokenEndpointAuthMethods.ClientSecretPost]);

        var httpContext = new DefaultHttpContext();
        httpContext.Request.Form = new FormCollection(new Dictionary<string, StringValues>
        {
            ["client_id"] = "client-1",
            ["client_secret"] = string.Empty,
        });

        var result = await composite.AuthenticateAsync("client-1", httpContext, TestContext.Current.CancellationToken);

        result.Authenticated.Should().BeFalse();
        hasher.CallCount.Should().Be(ClientSecrets.MaxActiveSecretsPerClient,
            "the client_secret_post path is entered and padded — not the none fallback");
    }

    [Theory]
    [InlineData(1, TokenEndpointAuthMethods.ClientSecretPost)]
    [InlineData(2, TokenEndpointAuthMethods.ClientSecretPost)]
    [InlineData(1, TokenEndpointAuthMethods.ClientSecretBasic)]
    [InlineData(2, TokenEndpointAuthMethods.ClientSecretBasic)]
    public async Task An_empty_secret_pads_the_full_budget_whatever_the_clients_secret_count(
        int secretCount, string method)
    {
        // An unknown client always costs the full budget. Were an empty secret tried against each
        // stored secret — no work at all for PBKDF2 — a one-secret client would cost one derivation
        // and a two-secret client none, and timing would reveal both that the client exists and
        // whether it is mid-rotation.
        var client = new MinimalClient
        {
            ClientId = "client-1",
            Secrets = [.. Enumerable.Range(0, secretCount).Select(_ => FakeSecret())],
            IsPublic = false,
            AllowedTokenEndpointAuthMethods = new HashSet<string>(StringComparer.Ordinal) { method },
        };
        var (composite, hasher) = CreateCompositeWithHasher(
            client,
            new FakeHasher(false),
            allowedMethods: [method]);

        var httpContext = method == TokenEndpointAuthMethods.ClientSecretBasic
            ? CreateHttpContextWithBasicAuth("client-1:", "client-1")
            : CreateHttpContextWithPostSecret("client-1", string.Empty);

        var result = await composite.AuthenticateAsync("client-1", httpContext, TestContext.Current.CancellationToken);

        result.Authenticated.Should().BeFalse();
        hasher.DerivationCount.Should().Be(ClientSecrets.MaxActiveSecretsPerClient);
    }

    private static DefaultHttpContext CreateHttpContextWithPostSecret(string clientId, string secret)
    {
        var ctx = new DefaultHttpContext();
        ctx.Request.Form = new FormCollection(new Dictionary<string, StringValues>
        {
            ["client_id"] = clientId,
            ["client_secret"] = secret,
        });
        return ctx;
    }

    // ── Malformed Basic credentials ───────────────────────────────────────────────────────────────

    [Fact]
    public async Task AuthenticateAsync_returns_Authenticated_false_when_Basic_header_contains_invalid_base64()
    {
        var secret = FakeSecret();
        var client = CreateConfidentialClient(secret: secret);
        var (composite, hasher) = CreateComposite(client, verifyResult: true);

        var httpContext = new DefaultHttpContext();
        httpContext.Request.Headers.Authorization = "Basic not-valid-base64!!!";
        httpContext.Request.Form = new FormCollection(new Dictionary<string, StringValues>
        {
            ["client_id"] = "client-1",
        });

        var result = await composite.AuthenticateAsync("client-1", httpContext, TestContext.Current.CancellationToken);

        result.Authenticated.Should().BeFalse(
            "a Basic header with invalid base64 must be rejected");
        hasher.CallCount.Should().Be(
            ClientSecrets.MaxActiveSecretsPerClient, "a malformed request is padded like a wrong secret");
    }

    [Fact]
    public async Task AuthenticateAsync_returns_Authenticated_false_when_Basic_header_contains_no_colon_separator()
    {
        var secret = FakeSecret();
        var client = CreateConfidentialClient(secret: secret);
        var (composite, hasher) = CreateComposite(client, verifyResult: true);

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
        hasher.CallCount.Should().Be(
            ClientSecrets.MaxActiveSecretsPerClient, "a malformed request is padded like a wrong secret");
    }

    // ── Security: throwing CanHandle is isolated ──────────────────────────────────────────────────

    [Fact]
    public async Task AuthenticateAsync_does_not_throw_when_CanHandle_throws()
    {
        var registry = Registry([new FakeHasher()]);
        var secrets = new ClientSecrets(registry, NullSanitizingLogger<ClientSecrets>.Instance);

        // ThrowingCanHandleAuthenticator is the only authenticator — after its CanHandle throws
        // and is suppressed, matches is empty → none fallback → rejected (none not in allowlist).
        var composite = new CompositeClientAuthenticator(
            [new ThrowingCanHandleAuthenticator()],
            Resolver(CreatePublicClient()),
            CreateServerOptions(TokenEndpointAuthMethods.ClientSecretBasic),
            secrets,
            NullSanitizingLogger<CompositeClientAuthenticator>.Instance);

        var httpContext = new DefaultHttpContext();
        httpContext.Request.Form = new FormCollection(new Dictionary<string, StringValues>
        {
            ["client_id"] = "public-client",
        });

        Func<Task> act = () =>
            composite.AuthenticateAsync("public-client", httpContext, TestContext.Current.CancellationToken).AsTask();

        await act.Should().NotThrowAsync(
            "a throwing CanHandle must be caught and treated as non-matching, not propagated");

        var result = await composite.AuthenticateAsync("public-client", httpContext, TestContext.Current.CancellationToken);
        result.Authenticated.Should().BeFalse(
            "no authenticator matched so the none fallback fires, and none is not in the server allowlist");
    }

    [Fact]
    public async Task AuthenticateAsync_logs_error_when_CanHandle_throws()
    {
        var registry = Registry([new FakeHasher()]);
        var secrets = new ClientSecrets(registry, NullSanitizingLogger<ClientSecrets>.Instance);

        var logger = new CapturingSanitizingLogger<CompositeClientAuthenticator>();

        var composite = new CompositeClientAuthenticator(
            [new ThrowingCanHandleAuthenticator()],
            Resolver(CreatePublicClient()),
            CreateServerOptions(TokenEndpointAuthMethods.ClientSecretBasic),
            secrets,
            logger);

        var httpContext = new DefaultHttpContext();
        httpContext.Request.Form = new FormCollection(new Dictionary<string, StringValues>
        {
            ["client_id"] = "public-client",
        });

        await composite.AuthenticateAsync("public-client", httpContext, TestContext.Current.CancellationToken);

        logger.Entries.Should().ContainSingle()
            .Which.Level.Should().Be(LogLevel.Error);
        logger.Entries[0].Exception.Should().BeOfType<RedactedExceptionWrapper>()
            .Which.OriginalExceptionType.Should().Be(typeof(InvalidOperationException).FullName);
    }

    // ── Security: CanHandle returns undeclared method → rejected ──────────────────────────────────

    [Fact]
    public async Task AuthenticateAsync_returns_Authenticated_false_when_CanHandle_returns_method_not_declared_in_AuthenticationMethods()
    {
        // Authenticator declares "client_secret_basic" but CanHandle returns "undeclared_method".
        // The guard at line 112–113 detects the mismatch and rejects without invoking AuthenticateAsync.
        var mismatchedAuthenticator = new MismatchedMethodAuthenticator(
            declared: "client_secret_basic",
            returned: "undeclared_method");

        var registry = Registry([new FakeHasher()]);
        var secrets = new ClientSecrets(registry, NullSanitizingLogger<ClientSecrets>.Instance);

        var client = CreateConfidentialClient(
            allowedMethod: "undeclared_method");

        var composite = new CompositeClientAuthenticator(
            [mismatchedAuthenticator],
            Resolver(client),
            CreateServerOptions("client_secret_basic", "undeclared_method"),
            secrets,
            NullSanitizingLogger<CompositeClientAuthenticator>.Instance);

        var httpContext = new DefaultHttpContext();
        httpContext.Request.Form = new FormCollection(new Dictionary<string, StringValues>
        {
            ["client_id"] = "client-1",
        });

        var result = await composite.AuthenticateAsync("client-1", httpContext, TestContext.Current.CancellationToken);

        result.Authenticated.Should().BeFalse();
    }

    // ── Security: matched method absent from server allowlist → rejected ───────────────────────────

    [Fact]
    public async Task AuthenticateAsync_returns_Authenticated_false_when_matched_method_is_not_in_server_allowlist()
    {
        // Authenticator declares and returns "custom_method"; server only allows "client_secret_basic".
        // The guard at line 116–117 rejects because "custom_method" is not in AuthMethodsSupported.
        var customAuthenticator = new AlwaysHandlesAuthenticator("custom_method");

        var registry = Registry([new FakeHasher()]);
        var secrets = new ClientSecrets(registry, NullSanitizingLogger<ClientSecrets>.Instance);

        var client = new MinimalClient
        {
            ClientId = "client-1",
            Secrets = [],
            IsPublic = false,
            AllowedTokenEndpointAuthMethods =
                new HashSet<string>(StringComparer.Ordinal) { "custom_method" },
        };

        var composite = new CompositeClientAuthenticator(
            [customAuthenticator],
            Resolver(client),
            CreateServerOptions("client_secret_basic"),
            secrets,
            NullSanitizingLogger<CompositeClientAuthenticator>.Instance);

        var httpContext = new DefaultHttpContext();
        httpContext.Request.Form = new FormCollection(new Dictionary<string, StringValues>
        {
            ["client_id"] = "client-1",
        });

        var result = await composite.AuthenticateAsync("client-1", httpContext, TestContext.Current.CancellationToken);

        result.Authenticated.Should().BeFalse();
    }

    // ── Security: none fallback guard — unknown client pads timing ────────────────────────────────

    [Fact]
    public async Task A_public_client_refused_because_the_server_disallows_none_is_padded_like_an_unknown_client()
    {
        var hasher = new FakeHasher();
        var secrets = new ClientSecrets(Registry([hasher]), NullSanitizingLogger<ClientSecrets>.Instance);
        var composite = new CompositeClientAuthenticator(
            [new ClientSecretAuthenticator(secrets)],
            Resolver(CreatePublicClient()),
            CreateServerOptions(TokenEndpointAuthMethods.ClientSecretBasic),
            secrets,
            NullSanitizingLogger<CompositeClientAuthenticator>.Instance);

        var result = await composite.AuthenticateAsync(
            "public-client", new DefaultHttpContext(), TestContext.Current.CancellationToken);

        result.Authenticated.Should().BeFalse();
        hasher.CallCount.Should().Be(ClientSecrets.MaxActiveSecretsPerClient);
    }

    [Fact]
    public async Task AuthenticateAsync_returns_Authenticated_false_and_pads_timing_for_unknown_client_on_none_fallback()
    {
        var hasher = new FakeHasher();
        var registry = Registry([hasher]);
        var secrets = new ClientSecrets(registry, NullSanitizingLogger<ClientSecrets>.Instance);

        var composite = new CompositeClientAuthenticator(
            [new ClientSecretAuthenticator(secrets)],
            Resolver(null),
            CreateServerOptions(TokenEndpointAuthMethods.None),
            secrets,
            NullSanitizingLogger<CompositeClientAuthenticator>.Instance);

        var httpContext = new DefaultHttpContext();

        var result = await composite.AuthenticateAsync("unknown-client", httpContext, TestContext.Current.CancellationToken);

        result.Authenticated.Should().BeFalse();
        hasher.CallCount.Should().Be(ClientSecrets.MaxActiveSecretsPerClient);
    }

    // ── Security: none fallback guard — corrupt client with credentials pads timing ──────────────

    [Fact]
    public async Task AuthenticateAsync_returns_Authenticated_false_and_pads_timing_for_corrupt_public_client_with_credentials()
    {
        var hasher = new FakeHasher();

        var corruptClient = new MinimalClient
        {
            ClientId = "corrupt-client",
            Secrets = [FakeSecret()],
            IsPublic = true,
            AllowedTokenEndpointAuthMethods =
                new HashSet<string>(StringComparer.Ordinal) { TokenEndpointAuthMethods.None },
        };

        var (composite, resolverLogger) = CreateValidatingComposite(corruptClient, hasher);

        var httpContext = new DefaultHttpContext();

        var result = await composite.AuthenticateAsync("corrupt-client", httpContext, TestContext.Current.CancellationToken);

        result.Authenticated.Should().BeFalse();
        hasher.DerivationCount.Should().Be(ClientSecrets.MaxActiveSecretsPerClient);
        resolverLogger.Entries.Should().ContainSingle(e => e.Message.Contains(TrinityViolation));
    }

    // ── Security: none fallback guard — corrupt client with extra auth methods pads timing ────────

    [Fact]
    public async Task AuthenticateAsync_returns_Authenticated_false_and_pads_timing_for_corrupt_public_client_with_extra_auth_methods()
    {
        var hasher = new FakeHasher();

        var corruptClient = new MinimalClient
        {
            ClientId = "corrupt-client",
            Secrets = [],
            IsPublic = true,
            AllowedTokenEndpointAuthMethods =
                new HashSet<string>(StringComparer.Ordinal)
                {
                    TokenEndpointAuthMethods.ClientSecretBasic,
                    TokenEndpointAuthMethods.None,
                },
        };

        var (composite, resolverLogger) = CreateValidatingComposite(corruptClient, hasher);

        var httpContext = new DefaultHttpContext();

        var result = await composite.AuthenticateAsync("corrupt-client", httpContext, TestContext.Current.CancellationToken);

        result.Authenticated.Should().BeFalse();
        hasher.CallCount.Should().Be(ClientSecrets.MaxActiveSecretsPerClient);
        resolverLogger.Entries.Should().ContainSingle(e => e.Message.Contains(TrinityViolation));
    }
}
