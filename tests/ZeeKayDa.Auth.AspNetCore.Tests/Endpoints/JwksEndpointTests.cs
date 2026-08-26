using System.Buffers.Text;
using System.Net;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using ZeeKayDa.Auth.Authorization;
using ZeeKayDa.Auth.Clients;
using ZeeKayDa.Auth.Extensions;
using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.AspNetCore.Tests.Endpoints;

public sealed class JwksEndpointTests : IDisposable
{
    private const string JwksPath = "/connect/jwks";

    private readonly TestWebAppFactory _factory;
    private readonly HttpClient _client;

    public JwksEndpointTests()
    {
        _factory = new TestWebAppFactory();
        _client = CreateClient(_factory);
    }

    public void Dispose()
    {
        _client.Dispose();
        _factory.Dispose();
    }

    private static HttpClient CreateClient(
        WebApplicationFactory<TestWebAppFactory> factory,
        string baseAddress = "https://test.example.com")
        => factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            BaseAddress = new Uri(baseAddress),
        });

    /// <summary>
    /// A factory whose signing source fills the requested slots: RSA keys in
    /// <c>Previous</c>/<c>Current</c>, an EC key in <c>Next</c>.
    /// </summary>
    private static TestWebAppFactory CreateMultiSlotFactory(
        bool includePrevious, bool includeNext)
        => new(configureBuilder: builder => builder.Services.AddZeeKayDaSigningKeySource(
            _ => new MultiSlotSigningKeySource(includePrevious, includeNext)));

    private sealed class MultiSlotSigningKeySource(bool includePrevious, bool includeNext)
        : ISigningKeySource, IDisposable
    {
        private readonly RSA _previous = RSA.Create(2048);
        private readonly RSA _current = RSA.Create(2048);
        private readonly ECDsa _next = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        public ValueTask<SourceKeySet> ReadAsync(CancellationToken cancellationToken = default)
        {
            var previous = includePrevious
                ? new SourceKey(
                    new SourceKeyId("previous-key"),
                    SigningAlgorithm.RS256,
                    PublicKeyParameters.FromRsa(_previous.ExportParameters(includePrivateParameters: false)),
                    ExpiresAt: null)
                : null;
            var current = new SourceKey(
                new SourceKeyId("current-key"),
                SigningAlgorithm.RS256,
                PublicKeyParameters.FromRsa(_current.ExportParameters(includePrivateParameters: false)),
                ExpiresAt: null);
            var next = includeNext
                ? new SourceKey(
                    new SourceKeyId("next-key"),
                    SigningAlgorithm.ES256,
                    PublicKeyParameters.FromEc(_next.ExportParameters(includePrivateParameters: false)),
                    ExpiresAt: null)
                : null;

            return new ValueTask<SourceKeySet>(SourceKeySet.Create(previous, current, next));
        }

        public ValueTask<ISigner> CreateSignerAsync(SourceKeyId id, CancellationToken cancellationToken = default)
        {
            id.Value.Should().Be("current-key", because: "only the Current slot's key ever signs");

            // A fresh private key instance: the ring owns and disposes what it is handed.
            var privateKey = RSA.Create(_current.ExportParameters(includePrivateParameters: true));
            return new ValueTask<ISigner>(new LocalSigner(SigningAlgorithm.RS256, privateKey));
        }

        public void Dispose()
        {
            _previous.Dispose();
            _current.Dispose();
            _next.Dispose();
        }
    }

    private sealed class TestClient : IClientMetadata
    {
        public string ClientId => "test-client";
        public bool IsPublic => true;
        public IReadOnlySet<string> RedirectUris => new HashSet<string>();
        public IReadOnlySet<string> PostLogoutRedirectUris => new HashSet<string>();
        public IReadOnlySet<string> AllowedScopes => new HashSet<string>();
        public IReadOnlySet<GrantType> AllowedGrantTypes => new HashSet<GrantType>();
        public IReadOnlySet<ResponseType> AllowedResponseTypes => new HashSet<ResponseType>();
        public IReadOnlySet<ResponseMode> AllowedResponseModes => new HashSet<ResponseMode>();
        public IReadOnlySet<string> AllowedTokenEndpointAuthMethods => new HashSet<string>();
        public bool EnableZkdErrorCodes => false;
    }

    // ── Status code and content type ─────────────────────────────────────────────────────────────

    [Fact]
    public async Task GetJwks_returns_200()
    {
        var response = await _client.GetAsync(JwksPath, TestContext.Current.CancellationToken);

        response.StatusCode.Should().Be(HttpStatusCode.OK);
    }

    [Fact]
    public async Task GetJwks_returns_jwk_set_content_type()
    {
        var response = await _client.GetAsync(JwksPath, TestContext.Current.CancellationToken);

        response.Content.Headers.ContentType?.MediaType.Should().Be("application/jwk-set+json");
    }

    // ── Response body ────────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task GetJwks_returns_a_single_jwk_with_all_required_members_for_a_Current_only_configuration()
    {
        var doc = await _client.GetFromJsonAsync<JsonDocument>(
            JwksPath, TestContext.Current.CancellationToken);

        var keys = doc!.RootElement.GetProperty("keys");
        keys.GetArrayLength().Should().Be(1);
        var jwk = keys[0];
        jwk.GetProperty("kty").GetString().Should().Be("RSA");
        jwk.GetProperty("use").GetString().Should().Be("sig");
        jwk.GetProperty("alg").GetString().Should().Be("RS256");
        jwk.GetProperty("kid").GetString().Should().NotBeNullOrEmpty();
        jwk.GetProperty("n").GetString().Should().NotBeNullOrEmpty();
        jwk.GetProperty("e").GetString().Should().NotBeNullOrEmpty();
    }

    [Fact]
    public async Task GetJwks_publishes_every_configured_slot()
    {
        using var factory = CreateMultiSlotFactory(includePrevious: true, includeNext: true);
        using var client = CreateClient(factory);

        var doc = await client.GetFromJsonAsync<JsonDocument>(
            JwksPath, TestContext.Current.CancellationToken);

        var ring = factory.Services.GetRequiredService<ISigningKeyRing>();
        doc!.RootElement.GetProperty("keys").EnumerateArray()
            .Select(jwk => jwk.GetProperty("kid").GetString())
            .Should().Equal(ring.Current.Published.Select(key => key.Kid));
    }

    [Fact]
    public async Task GetJwks_returns_no_private_key_member_for_a_fully_populated_ring()
    {
        using var factory = CreateMultiSlotFactory(includePrevious: true, includeNext: true);
        using var client = CreateClient(factory);

        var doc = await client.GetFromJsonAsync<JsonDocument>(
            JwksPath, TestContext.Current.CancellationToken);

        var allowedMembers = new[] { "kid", "kty", "use", "alg", "n", "e", "crv", "x", "y" };
        var keys = doc!.RootElement.GetProperty("keys");
        keys.GetArrayLength().Should().Be(3);
        foreach (var jwk in keys.EnumerateArray())
        {
            jwk.EnumerateObject().Select(member => member.Name)
                .Should().BeSubsetOf(allowedMembers);
        }
    }

    [Fact]
    public async Task GetJwks_returns_byte_identical_responses_across_repeated_requests()
    {
        var first = await _client.GetByteArrayAsync(JwksPath, TestContext.Current.CancellationToken);
        var second = await _client.GetByteArrayAsync(JwksPath, TestContext.Current.CancellationToken);

        second.Should().Equal(first);
    }

    // ── Agreement with issued tokens ─────────────────────────────────────────────────────────────

    [Fact]
    public async Task GetJwks_kid_matches_the_kid_in_the_header_of_a_token_issued_at_the_same_moment()
    {
        var doc = await _client.GetFromJsonAsync<JsonDocument>(
            JwksPath, TestContext.Current.CancellationToken);
        var publishedKid = doc!.RootElement.GetProperty("keys")[0].GetProperty("kid").GetString();

        var tokenKid = await IssueIdTokenAndReadHeaderKid(_factory);

        tokenKid.Should().Be(publishedKid);
    }

    [Fact]
    public async Task GetJwks_publishes_Previous_and_Next_keys_but_only_Current_ever_signs()
    {
        using var factory = CreateMultiSlotFactory(includePrevious: true, includeNext: true);
        using var client = CreateClient(factory);

        var doc = await client.GetFromJsonAsync<JsonDocument>(
            JwksPath, TestContext.Current.CancellationToken);
        var publishedKids = doc!.RootElement.GetProperty("keys").EnumerateArray()
            .Select(jwk => jwk.GetProperty("kid").GetString())
            .ToList();

        var ring = factory.Services.GetRequiredService<ISigningKeyRing>();
        var currentKid = ring.Current.SigningKey.Kid;
        var tokenKid = await IssueIdTokenAndReadHeaderKid(factory);

        publishedKids.Should().HaveCount(3).And.Contain(currentKid);
        tokenKid.Should().Be(currentKid);
    }

    private static async Task<string?> IssueIdTokenAndReadHeaderKid(TestWebAppFactory factory)
    {
        var issuer = factory.Services.GetRequiredKeyedService<ITokenIssuer>(TokenKind.IdToken);
        var token = await issuer.IssueAsync(
            new TokenIssuanceContext(new TestClient(), TokenKind.IdToken),
            new TokenPayload(new Dictionary<string, object?> { ["sub"] = "user-1" }),
            TestContext.Current.CancellationToken);

        var headerSegment = token.Value.Split('.')[0];
        var headerBytes = Base64Url.DecodeFromChars(headerSegment);
        using var header = JsonDocument.Parse(headerBytes);
        return header.RootElement.GetProperty("kid").GetString();
    }

    // ── Cache-Control ────────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task GetJwks_returns_Cache_Control_public_max_age_3600_by_default()
    {
        var response = await _client.GetAsync(JwksPath, TestContext.Current.CancellationToken);

        response.Headers.CacheControl.Should().NotBeNull();
        response.Headers.CacheControl!.Public.Should().BeTrue();
        response.Headers.CacheControl!.MaxAge.Should().Be(TimeSpan.FromSeconds(3600));
    }

    [Fact]
    public async Task GetJwks_reflects_custom_cache_max_age_in_header()
    {
        using var factory = new TestWebAppFactory(opts =>
            opts.JwksEndpoint.CacheMaxAge = TimeSpan.FromSeconds(300));
        using var client = CreateClient(factory);

        var response = await client.GetAsync(JwksPath, TestContext.Current.CancellationToken);

        response.Headers.CacheControl!.ToString().Should().Contain("max-age=300");
    }

    [Fact]
    public async Task GetJwks_returns_no_store_for_zero_cache_max_age()
    {
        using var factory = new TestWebAppFactory(opts =>
            opts.JwksEndpoint.CacheMaxAge = TimeSpan.Zero);
        using var client = CreateClient(factory);

        var response = await client.GetAsync(JwksPath, TestContext.Current.CancellationToken);

        response.Headers.CacheControl!.ToString().Should().Be("no-store");
    }

    // ── CORS ─────────────────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task GetJwks_returns_wildcard_CORS_and_no_Vary_Origin_for_empty_allow_list()
    {
        var response = await _client.GetAsync(JwksPath, TestContext.Current.CancellationToken);

        response.Headers.TryGetValues("Access-Control-Allow-Origin", out var values).Should().BeTrue();
        values.Should().ContainSingle().Which.Should().Be("*");
        var varyValues = response.Headers.Vary.SelectMany(v => v.Split(',').Select(s => s.Trim()));
        varyValues.Should().NotContain("Origin", because: "wildcard CORS does not require Vary: Origin");
    }

    [Fact]
    public async Task GetJwks_returns_specific_origin_and_Vary_Origin_for_matching_origin_in_explicit_allow_list()
    {
        using var factory = new TestWebAppFactory(opts =>
            opts.JwksEndpoint.CorsOrigins.Add("https://app.example.com"));
        using var client = CreateClient(factory);
        client.DefaultRequestHeaders.Add("Origin", "https://app.example.com");

        var response = await client.GetAsync(JwksPath, TestContext.Current.CancellationToken);

        response.Headers.TryGetValues("Access-Control-Allow-Origin", out var values).Should().BeTrue();
        values.Should().ContainSingle().Which.Should().Be("https://app.example.com");
        var varyValues = response.Headers.Vary.SelectMany(v => v.Split(',').Select(s => s.Trim()));
        varyValues.Should().Contain("Origin");
    }

    [Fact]
    public async Task GetJwks_has_no_ACAO_header_but_still_Vary_Origin_for_non_matching_origin_in_explicit_allow_list()
    {
        using var factory = new TestWebAppFactory(opts =>
            opts.JwksEndpoint.CorsOrigins.Add("https://app.example.com"));
        using var client = CreateClient(factory);
        client.DefaultRequestHeaders.Add("Origin", "https://evil.example.com");

        var response = await client.GetAsync(JwksPath, TestContext.Current.CancellationToken);

        response.Headers.TryGetValues("Access-Control-Allow-Origin", out _).Should().BeFalse();
        var varyValues = response.Headers.Vary.SelectMany(v => v.Split(',').Select(s => s.Trim()));
        varyValues.Should().Contain("Origin");
    }

    // ── Routing ──────────────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task GetJwks_serves_the_published_URI_when_an_explicit_override_is_configured()
    {
        using var factory = new TestWebAppFactory(opts =>
        {
            opts.Issuer = "https://login.example.com";
            opts.JwksEndpoint.Uri = "https://login.example.com/keys";
        });
        using var client = CreateClient(factory, "https://login.example.com");

        var response = await client.GetAsync("/keys", TestContext.Current.CancellationToken);

        response.StatusCode.Should().Be(HttpStatusCode.OK);
        var doc = await response.Content.ReadFromJsonAsync<JsonDocument>(
            TestContext.Current.CancellationToken);
        doc!.RootElement.GetProperty("keys").GetArrayLength().Should().Be(1);
    }

    [Fact]
    public async Task GetJwks_registers_at_Issuer_prefixed_path_for_path_bearing_Issuer()
    {
        using var factory = new TestWebAppFactory(opts => opts.Issuer = "https://test.example.com/tenant1");
        using var client = CreateClient(factory);

        var response = await client.GetAsync("/tenant1/connect/jwks", TestContext.Current.CancellationToken);

        response.StatusCode.Should().Be(HttpStatusCode.OK);
    }

    [Fact]
    public async Task GetJwks_returns_404_for_wrong_host()
    {
        using var client = CreateClient(_factory, "https://other.example.com");

        var response = await client.GetAsync(JwksPath, TestContext.Current.CancellationToken);

        response.StatusCode.Should().Be(HttpStatusCode.NotFound);
    }
}
