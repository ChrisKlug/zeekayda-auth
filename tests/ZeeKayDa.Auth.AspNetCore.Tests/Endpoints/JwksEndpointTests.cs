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

    // ── Anonymous access ─────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task GetJwks_returns_200_under_a_host_wide_fallback_authorization_policy()
    {
        using var factory = new TestWebAppFactoryWithFallbackAuthorizationPolicy();
        using var client = CreateClient(factory);

        // The canary proves the fallback policy is actually enforced on this host...
        var hostRoute = await client.GetAsync("/host-route", TestContext.Current.CancellationToken);
        hostRoute.StatusCode.Should().Be(HttpStatusCode.Unauthorized);

        // ...and the JWKS must remain anonymously readable regardless.
        var response = await client.GetAsync(JwksPath, TestContext.Current.CancellationToken);
        response.StatusCode.Should().Be(HttpStatusCode.OK);
    }

    // ── Signature round-trip ─────────────────────────────────────────────────────────────────────

    [Theory]
    [InlineData(SigningAlgorithm.RS256)]
    [InlineData(SigningAlgorithm.ES256)]
    [InlineData(SigningAlgorithm.ES384)]
    [InlineData(SigningAlgorithm.ES512)]
    public async Task GetJwks_served_key_verifies_the_signature_of_a_token_this_server_issued(
        SigningAlgorithm algorithm)
    {
        using var factory = new TestWebAppFactory(configureBuilder: builder =>
            builder.Services.AddZeeKayDaSigningKeySource(
                _ => new SingleAlgorithmSigningKeySource(algorithm)));
        using var client = CreateClient(factory);

        var issuer = factory.Services.GetRequiredKeyedService<ITokenIssuer>(TokenKind.IdToken);
        var token = await issuer.IssueAsync(
            new TokenIssuanceContext(new TestClient(), TokenKind.IdToken),
            new TokenPayload(new Dictionary<string, object?> { ["sub"] = "user-1" }),
            TestContext.Current.CancellationToken);

        var doc = await client.GetFromJsonAsync<JsonDocument>(
            JwksPath, TestContext.Current.CancellationToken);
        var parts = token.Value.Split('.');
        using var header = JsonDocument.Parse(Base64Url.DecodeFromChars(parts[0]));
        var tokenKid = header.RootElement.GetProperty("kid").GetString();
        var jwk = doc!.RootElement.GetProperty("keys").EnumerateArray()
            .Single(key => key.GetProperty("kid").GetString() == tokenKid);

        var signingInput = Encoding.ASCII.GetBytes($"{parts[0]}.{parts[1]}");
        var signature = Base64Url.DecodeFromChars(parts[2]);
        VerifyWithServedJwk(jwk, algorithm, signingInput, signature).Should().BeTrue(
            because: "a relying party importing the served JWK must be able to verify the token");
    }

    private static bool VerifyWithServedJwk(
        JsonElement jwk, SigningAlgorithm algorithm, byte[] signingInput, byte[] signature)
    {
        if (algorithm == SigningAlgorithm.RS256)
        {
            using var rsa = RSA.Create(new RSAParameters
            {
                Modulus = Base64Url.DecodeFromChars(jwk.GetProperty("n").GetString()),
                Exponent = Base64Url.DecodeFromChars(jwk.GetProperty("e").GetString()),
            });
            return rsa.VerifyData(
                signingInput, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        }

        var (curve, hash) = algorithm switch
        {
            SigningAlgorithm.ES256 => (ECCurve.NamedCurves.nistP256, HashAlgorithmName.SHA256),
            SigningAlgorithm.ES384 => (ECCurve.NamedCurves.nistP384, HashAlgorithmName.SHA384),
            _ => (ECCurve.NamedCurves.nistP521, HashAlgorithmName.SHA512),
        };
        jwk.GetProperty("crv").GetString().Should().Be(algorithm switch
        {
            SigningAlgorithm.ES256 => "P-256",
            SigningAlgorithm.ES384 => "P-384",
            _ => "P-521",
        });
        using var ecdsa = ECDsa.Create(new ECParameters
        {
            Curve = curve,
            Q = new ECPoint
            {
                X = Base64Url.DecodeFromChars(jwk.GetProperty("x").GetString()),
                Y = Base64Url.DecodeFromChars(jwk.GetProperty("y").GetString()),
            },
        });
        return ecdsa.VerifyData(signingInput, signature, hash);
    }

    private sealed class SingleAlgorithmSigningKeySource : ISigningKeySource, IDisposable
    {
        private readonly SigningAlgorithm _algorithm;
        private readonly RSA? _rsa;
        private readonly ECDsa? _ecdsa;

        public SingleAlgorithmSigningKeySource(SigningAlgorithm algorithm)
        {
            _algorithm = algorithm;
            if (algorithm == SigningAlgorithm.RS256)
                _rsa = RSA.Create(2048);
            else
                _ecdsa = ECDsa.Create(algorithm switch
                {
                    SigningAlgorithm.ES256 => ECCurve.NamedCurves.nistP256,
                    SigningAlgorithm.ES384 => ECCurve.NamedCurves.nistP384,
                    _ => ECCurve.NamedCurves.nistP521,
                });
        }

        public ValueTask<SourceKeySet> ReadAsync(CancellationToken cancellationToken = default)
        {
            var publicKey = _rsa is not null
                ? PublicKeyParameters.FromRsa(_rsa.ExportParameters(includePrivateParameters: false))
                : PublicKeyParameters.FromEc(_ecdsa!.ExportParameters(includePrivateParameters: false));
            var current = new SourceKey(
                new SourceKeyId("current-key"), _algorithm, publicKey, ExpiresAt: null);

            return new ValueTask<SourceKeySet>(SourceKeySet.Create(previous: null, current, next: null));
        }

        public ValueTask<ISigner> CreateSignerAsync(SourceKeyId id, CancellationToken cancellationToken = default)
        {
            // A fresh private key instance: the ring owns and disposes what it is handed.
            AsymmetricAlgorithm privateKey = _rsa is not null
                ? RSA.Create(_rsa.ExportParameters(includePrivateParameters: true))
                : ECDsa.Create(_ecdsa!.ExportParameters(includePrivateParameters: true));
            return new ValueTask<ISigner>(new LocalSigner(_algorithm, privateKey));
        }

        public void Dispose()
        {
            _rsa?.Dispose();
            _ecdsa?.Dispose();
        }
    }

    // ── Advertised jwks_uri agreement ────────────────────────────────────────────────────────────

    [Fact]
    public async Task GetJwks_serves_the_jwks_uri_the_discovery_document_advertises_for_a_path_bearing_Issuer()
    {
        using var factory = new TestWebAppFactory(opts => opts.Issuer = "https://test.example.com/tenant1");
        using var client = CreateClient(factory);

        var discovery = await client.GetFromJsonAsync<JsonDocument>(
            "/tenant1/.well-known/openid-configuration", TestContext.Current.CancellationToken);
        var jwksUri = new Uri(discovery!.RootElement.GetProperty("jwks_uri").GetString()!);

        jwksUri.Host.Should().Be("test.example.com");
        var response = await client.GetAsync(jwksUri.AbsolutePath, TestContext.Current.CancellationToken);

        response.StatusCode.Should().Be(HttpStatusCode.OK);
        var doc = await response.Content.ReadFromJsonAsync<JsonDocument>(
            TestContext.Current.CancellationToken);
        doc!.RootElement.GetProperty("keys").GetArrayLength().Should().BeGreaterThan(0);
    }

    [Fact]
    public async Task GetJwks_serves_the_jwks_uri_the_discovery_document_advertises_when_an_override_is_configured()
    {
        using var factory = new TestWebAppFactory(opts =>
        {
            opts.Issuer = "https://login.example.com";
            opts.JwksEndpoint.Uri = "https://login.example.com/keys";
        });
        using var client = CreateClient(factory, "https://login.example.com");

        var discovery = await client.GetFromJsonAsync<JsonDocument>(
            "/.well-known/openid-configuration", TestContext.Current.CancellationToken);
        var jwksUri = new Uri(discovery!.RootElement.GetProperty("jwks_uri").GetString()!);

        jwksUri.Should().Be(new Uri("https://login.example.com/keys"));
        var response = await client.GetAsync(jwksUri.AbsolutePath, TestContext.Current.CancellationToken);

        response.StatusCode.Should().Be(HttpStatusCode.OK);
        var doc = await response.Content.ReadFromJsonAsync<JsonDocument>(
            TestContext.Current.CancellationToken);
        doc!.RootElement.GetProperty("keys").GetArrayLength().Should().BeGreaterThan(0);
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
