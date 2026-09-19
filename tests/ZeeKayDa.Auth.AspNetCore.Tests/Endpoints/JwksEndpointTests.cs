using System.Buffers.Text;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.DependencyInjection;
using ZeeKayDa.Auth.AspNetCore.Endpoints;
using ZeeKayDa.Auth.Authorization;
using ZeeKayDa.Auth.Clients;
using ZeeKayDa.Auth.Extensions;
using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.AspNetCore.Tests.Endpoints;

/// <summary>
/// What the JWKS endpoint's handler produces for a request: the status, the response headers it
/// writes itself, and the body. Where the route is registered, whether the group's conventions
/// apply, and what a real host does for its own routing quirks all live in
/// <see cref="JwksEndpointHostTests"/>, because none of them is the handler's behaviour.
/// </summary>
public sealed class JwksEndpointTests
{
    private const string JwksPath = "/connect/jwks";

    private static Task<HttpResponseMessage> GetAsync(EndpointHost host, string? origin = null)
    {
        var request = host.Get(JwksPath);

        if (origin is not null)
            request.WithHeader("Origin", origin);

        return host.InvokeAsync<JwksEndpoint>(e => e.Handle, request);
    }

    private static async Task<JsonElement> GetDocumentAsync(EndpointHost host)
    {
        using var response = await GetAsync(host);
        var body = await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);

        return JsonDocument.Parse(body).RootElement;
    }

    /// <summary>
    /// A signing source that fills the requested slots: RSA keys in <c>Previous</c>/<c>Current</c>,
    /// an EC key in <c>Next</c>.
    /// </summary>
    private static EndpointHost CreateMultiSlotHost(bool includePrevious, bool includeNext)
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
        using var response = await GetAsync(EndpointHost.Default);

        response.StatusCode.Should().Be(HttpStatusCode.OK);
    }

    [Fact]
    public async Task GetJwks_returns_jwk_set_content_type()
    {
        using var response = await GetAsync(EndpointHost.Default);

        response.Content.Headers.ContentType?.MediaType.Should().Be("application/jwk-set+json");
    }

    // ── Response body ────────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task GetJwks_returns_a_single_jwk_with_all_required_members_for_a_Current_only_configuration()
    {
        var doc = await GetDocumentAsync(EndpointHost.Default);

        var keys = doc.GetProperty("keys");
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
        using var host = CreateMultiSlotHost(includePrevious: true, includeNext: true);

        var doc = await GetDocumentAsync(host);

        var ring = host.Resolve<ISigningKeyRing>();
        doc.GetProperty("keys").EnumerateArray()
            .Select(jwk => jwk.GetProperty("kid").GetString())
            .Should().Equal(ring.Current.Published.Select(key => key.Kid));
    }

    [Fact]
    public async Task GetJwks_returns_no_private_key_member_for_a_fully_populated_ring()
    {
        using var host = CreateMultiSlotHost(includePrevious: true, includeNext: true);

        var doc = await GetDocumentAsync(host);

        var allowedMembers = new[] { "kid", "kty", "use", "alg", "n", "e", "crv", "x", "y" };
        var keys = doc.GetProperty("keys");
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
        using var first = await GetAsync(EndpointHost.Default);
        var firstBytes = await first.Content.ReadAsByteArrayAsync(TestContext.Current.CancellationToken);
        using var second = await GetAsync(EndpointHost.Default);
        var secondBytes = await second.Content.ReadAsByteArrayAsync(TestContext.Current.CancellationToken);

        secondBytes.Should().Equal(firstBytes);
    }

    // ── Agreement with issued tokens ─────────────────────────────────────────────────────────────

    [Fact]
    public async Task GetJwks_kid_matches_the_kid_in_the_header_of_a_token_issued_at_the_same_moment()
    {
        var doc = await GetDocumentAsync(EndpointHost.Default);
        var publishedKid = doc.GetProperty("keys")[0].GetProperty("kid").GetString();

        var tokenKid = await IssueIdTokenAndReadHeaderKid(EndpointHost.Default.Services);

        tokenKid.Should().Be(publishedKid);
    }

    [Fact]
    public async Task GetJwks_publishes_Previous_and_Next_keys_but_only_Current_ever_signs()
    {
        using var host = CreateMultiSlotHost(includePrevious: true, includeNext: true);

        var doc = await GetDocumentAsync(host);
        var publishedKids = doc.GetProperty("keys").EnumerateArray()
            .Select(jwk => jwk.GetProperty("kid").GetString())
            .ToList();

        var ring = host.Resolve<ISigningKeyRing>();
        var currentKid = ring.Current.SigningKey.Kid;
        var tokenKid = await IssueIdTokenAndReadHeaderKid(host.Services);

        publishedKids.Should().HaveCount(3).And.Contain(currentKid);
        tokenKid.Should().Be(currentKid);
    }

    private static async Task<string?> IssueIdTokenAndReadHeaderKid(IServiceProvider services)
    {
        var issuer = services.GetRequiredKeyedService<ITokenIssuer>(TokenKind.IdToken);
        var token = await issuer.IssueAsync(
            new IdTokenIssuanceContext(new TestClient(), new IssuedToken("access-token", TokenKind.AccessToken)),
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
        using var response = await GetAsync(EndpointHost.Default);

        response.Headers.CacheControl.Should().NotBeNull();
        response.Headers.CacheControl!.Public.Should().BeTrue();
        response.Headers.CacheControl!.MaxAge.Should().Be(TimeSpan.FromSeconds(3600));
    }

    [Fact]
    public async Task GetJwks_reflects_custom_cache_max_age_in_header()
    {
        using var host = new EndpointHost(opts => opts.JwksEndpoint.CacheMaxAge = TimeSpan.FromSeconds(300));

        using var response = await GetAsync(host);

        response.Headers.CacheControl!.ToString().Should().Contain("max-age=300");
    }

    [Fact]
    public async Task GetJwks_returns_no_store_for_zero_cache_max_age()
    {
        using var host = new EndpointHost(opts => opts.JwksEndpoint.CacheMaxAge = TimeSpan.Zero);

        using var response = await GetAsync(host);

        response.Headers.CacheControl!.ToString().Should().Be("no-store");
    }

    // ── CORS ─────────────────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task GetJwks_returns_wildcard_CORS_and_no_Vary_Origin_for_empty_allow_list()
    {
        using var response = await GetAsync(EndpointHost.Default);

        response.Headers.TryGetValues("Access-Control-Allow-Origin", out var values).Should().BeTrue();
        values.Should().ContainSingle().Which.Should().Be("*");
        var varyValues = response.Headers.Vary.SelectMany(v => v.Split(',').Select(s => s.Trim()));
        varyValues.Should().NotContain("Origin", because: "wildcard CORS does not require Vary: Origin");
    }

    [Fact]
    public async Task GetJwks_returns_specific_origin_and_Vary_Origin_for_matching_origin_in_explicit_allow_list()
    {
        using var host = new EndpointHost(opts => opts.CorsOrigins.Add("https://app.example.com"));

        using var response = await GetAsync(host, origin: "https://app.example.com");

        response.Headers.TryGetValues("Access-Control-Allow-Origin", out var values).Should().BeTrue();
        values.Should().ContainSingle().Which.Should().Be("https://app.example.com");
        var varyValues = response.Headers.Vary.SelectMany(v => v.Split(',').Select(s => s.Trim()));
        varyValues.Should().Contain("Origin");
    }

    [Fact]
    public async Task GetJwks_has_no_ACAO_header_but_still_Vary_Origin_for_non_matching_origin_in_explicit_allow_list()
    {
        using var host = new EndpointHost(opts => opts.CorsOrigins.Add("https://app.example.com"));

        using var response = await GetAsync(host, origin: "https://evil.example.com");

        response.Headers.TryGetValues("Access-Control-Allow-Origin", out _).Should().BeFalse();
        var varyValues = response.Headers.Vary.SelectMany(v => v.Split(',').Select(s => s.Trim()));
        varyValues.Should().Contain("Origin");
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
        using var host = new EndpointHost(configureBuilder: builder =>
            builder.Services.AddZeeKayDaSigningKeySource(
                _ => new SingleAlgorithmSigningKeySource(algorithm)));
        await host.EnsureStartedAsync();

        var issuer = host.Services.GetRequiredKeyedService<ITokenIssuer>(TokenKind.IdToken);
        var token = await issuer.IssueAsync(
            new IdTokenIssuanceContext(new TestClient(), new IssuedToken("access-token", TokenKind.AccessToken)),
            new TokenPayload(new Dictionary<string, object?> { ["sub"] = "user-1" }),
            TestContext.Current.CancellationToken);

        var doc = await GetDocumentAsync(host);
        var parts = token.Value.Split('.');
        using var header = JsonDocument.Parse(Base64Url.DecodeFromChars(parts[0]));
        var tokenKid = header.RootElement.GetProperty("kid").GetString();
        var jwk = doc.GetProperty("keys").EnumerateArray()
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

    // ── Allowlist sharing with discovery ────────────────────────────────────────────────────────

    [Fact]
    public async Task One_allowlist_governs_the_JWKS_and_the_discovery_document_alike()
    {
        using var host = new EndpointHost(opts => opts.CorsOrigins.Add("https://app.example.com"));

        using var jwks = await GetAsync(host, origin: "https://app.example.com");
        var discoveryRequest = host.Get("/.well-known/openid-configuration").WithHeader("Origin", "https://app.example.com");
        using var discovery = await host.InvokeAsync<DiscoveryEndpoint>(e => e.Handle, discoveryRequest);

        jwks.Headers.GetValues("Access-Control-Allow-Origin").Should().ContainSingle()
            .Which.Should().Be("https://app.example.com");
        discovery.Headers.GetValues("Access-Control-Allow-Origin").Should().ContainSingle()
            .Which.Should().Be("https://app.example.com");
    }
}
