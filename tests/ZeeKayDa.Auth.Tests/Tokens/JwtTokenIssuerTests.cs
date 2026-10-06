using System.Buffers.Text;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Time.Testing;
using ZeeKayDa.Auth.Clients;
using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.Tests.Tokens;

/// <summary>
/// Exercises <see cref="JwtTokenIssuer"/>: the compact serialisation it assembles, the JOSE header
/// it builds inside the ring's signing callback, and the discipline that the signing key is
/// resolved exactly once per token.
/// </summary>
public sealed class JwtTokenIssuerTests
{
    private static readonly DateTimeOffset Epoch = new(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);

    private static readonly IClient Client = new TestClient();

    // ── Fakes ────────────────────────────────────────────────────────────────────────────────────

    private sealed class TestClient : IClient
    {
        public string ClientId => "test-client";
        public bool IsPublic => true;
        public IReadOnlySet<string> RedirectUris => new HashSet<string>();
        public IReadOnlySet<string> PostLogoutRedirectUris => new HashSet<string>();
        public IReadOnlySet<string> AllowedScopes => new HashSet<string>();
        public IReadOnlySet<GrantType> AllowedGrantTypes => new HashSet<GrantType>();
        public IReadOnlySet<ZeeKayDa.Auth.Authorization.ResponseType> AllowedResponseTypes => new HashSet<ZeeKayDa.Auth.Authorization.ResponseType>();
        public IReadOnlySet<ZeeKayDa.Auth.Authorization.ResponseMode> AllowedResponseModes => new HashSet<ZeeKayDa.Auth.Authorization.ResponseMode>();
        public IReadOnlySet<string> AllowedTokenEndpointAuthMethods => new HashSet<string>();
        public bool EnableZkdErrorCodes => false;
    }

    private sealed class WorkingSource(RSA rsa) : ISigningKeySource
    {
        public Task<IReadOnlyList<SourceKey>> ReadAsync(CancellationToken cancellationToken = default)
        {
            var current = new SourceKey(
                new SourceKeyId("current"),
                SigningAlgorithm.RS256,
                PublicKeyParameters.FromRsa(rsa.ExportParameters(includePrivateParameters: false)));
            return Task.FromResult<IReadOnlyList<SourceKey>>([current]);
        }

        public Task<ISigner> CreateSignerAsync(SourceKeyId id, CancellationToken cancellationToken = default)
        {
            // A copy, because LocalSigner takes ownership and the test still needs the original
            // for signature verification.
            var copy = RSA.Create();
            copy.ImportParameters(rsa.ExportParameters(includePrivateParameters: true));
            return Task.FromResult<ISigner>(new LocalSigner(SigningAlgorithm.RS256, copy));
        }
    }

    /// <summary>
    /// Counts signatures, so a test can prove how many times the issuer signed — the ring resolves
    /// the key once per signature. The count starts after the ring's own startup self-test.
    /// </summary>
    private sealed class CountingSigner(ISigner inner) : ISigner
    {
        public int SignatureCount { get; private set; }

        public Task<ReadOnlyMemory<byte>> SignAsync(ReadOnlyMemory<byte> signingInput, CancellationToken cancellationToken = default)
        {
            SignatureCount++;
            return inner.SignAsync(signingInput, cancellationToken);
        }

        public void Reset() => SignatureCount = 0;

        public void Dispose() => inner.Dispose();
    }

    private static (JwtTokenIssuer Issuer, CountingSigner Signer) CreateCountingIssuer()
    {
        CountingSigner? signer = null;
        using var privateKey = TestSigningKeys.PrivateKey(SigningAlgorithm.RS256);
        var ring = TestSigningKeys.Ring(
            [TestSigningKeys.SourceKey("current", SigningAlgorithm.RS256, privateKey)],
            privateKey,
            decorateSigner: inner => signer = new CountingSigner(inner));
        signer!.Reset();
        return (new JwtTokenIssuer(ring), signer);
    }

    /// <summary>
    /// The acceptance criterion's opaque test double: implements <see cref="ITokenIssuer"/> with no
    /// reference to any JWS-specific type — no ring, no key, no signing input.
    /// </summary>
    private sealed class OpaqueTokenIssuer : ITokenIssuer
    {
        public Task<IssuedToken> IssueAsync(
            TokenIssuanceContext context, TokenPayload payload, CancellationToken cancellationToken = default)
            => Task.FromResult<IssuedToken>(new IssuedToken("opaque-handle-42", context is IdTokenIssuanceContext ? TokenKind.IdToken : TokenKind.AccessToken));
    }

    /// <summary>A client that restricted the algorithms its ID tokens may be signed with.</summary>
    private sealed class RestrictedClient(IReadOnlySet<SigningAlgorithm>? allowed) : IClient
    {
        public string ClientId => "restricted-client";
        public bool IsPublic => true;
        public IReadOnlySet<string> RedirectUris => new HashSet<string>();
        public IReadOnlySet<string> PostLogoutRedirectUris => new HashSet<string>();
        public IReadOnlySet<string> AllowedScopes => new HashSet<string>();
        public IReadOnlySet<GrantType> AllowedGrantTypes => new HashSet<GrantType>();
        public IReadOnlySet<ZeeKayDa.Auth.Authorization.ResponseType> AllowedResponseTypes => new HashSet<ZeeKayDa.Auth.Authorization.ResponseType>();
        public IReadOnlySet<ZeeKayDa.Auth.Authorization.ResponseMode> AllowedResponseModes => new HashSet<ZeeKayDa.Auth.Authorization.ResponseMode>();
        public IReadOnlySet<string> AllowedTokenEndpointAuthMethods => new HashSet<string>();
        public bool EnableZkdErrorCodes => false;
        public IReadOnlySet<SigningAlgorithm>? AllowedSigningAlgorithms => allowed;
    }

    /// <summary>A source over one EC key, for the algorithms whose hash is not SHA-256.</summary>
    private sealed class EcSource(ECDsa ecdsa, SigningAlgorithm algorithm) : ISigningKeySource
    {
        public Task<IReadOnlyList<SourceKey>> ReadAsync(CancellationToken cancellationToken = default)
        {
            var current = new SourceKey(
                new SourceKeyId("current"),
                algorithm,
                PublicKeyParameters.FromEc(ecdsa.ExportParameters(includePrivateParameters: false)));
            return Task.FromResult<IReadOnlyList<SourceKey>>([current]);
        }

        public Task<ISigner> CreateSignerAsync(SourceKeyId id, CancellationToken cancellationToken = default)
        {
            var copy = ECDsa.Create(ecdsa.ExportParameters(includePrivateParameters: true));
            return Task.FromResult<ISigner>(new LocalSigner(algorithm, copy));
        }
    }

    // ── Compact serialisation and signature ──────────────────────────────────────────────────────

    [Fact]
    public async Task IssueAsync_produces_a_JWS_whose_signature_verifies_against_the_signing_key()
    {
        using var rsa = RSA.Create(2048);
        var (issuer, _) = await CreateIssuerAsync(rsa);

        var token = await issuer.IssueAsync(
            new AccessTokenIssuanceContext(Client),
            new TokenPayload(new Dictionary<string, object?> { ["sub"] = "alice" }),
            TestContext.Current.CancellationToken);

        var parts = token.Value.Split('.');
        parts.Should().HaveCount(3);
        var verified = rsa.VerifyData(
            Encoding.ASCII.GetBytes($"{parts[0]}.{parts[1]}"),
            Base64Url.DecodeFromChars(parts[2]),
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);
        verified.Should().BeTrue();
    }

    [Fact]
    public async Task IssueAsync_header_kid_and_alg_match_the_key_that_signed()
    {
        using var rsa = RSA.Create(2048);
        var (issuer, ring) = await CreateIssuerAsync(rsa);

        var token = await issuer.IssueAsync(
            new AccessTokenIssuanceContext(Client),
            new TokenPayload(new Dictionary<string, object?>()),
            TestContext.Current.CancellationToken);

        var header = ParseSegment(token.Value.Split('.')[0]);
        header.GetProperty("kid").GetString().Should().Be(ring.Current.SigningKey.Kid);
        header.GetProperty("alg").GetString().Should().Be("RS256");
    }

    [Fact]
    public async Task IssueAsync_serialises_claims_verbatim_into_the_payload_segment()
    {
        using var rsa = RSA.Create(2048);
        var (issuer, _) = await CreateIssuerAsync(rsa);

        var token = await issuer.IssueAsync(
            new AccessTokenIssuanceContext(Client),
            new TokenPayload(new Dictionary<string, object?>
            {
                ["sub"] = "alice",
                ["aud"] = new[] { "api-one", "api-two" },
                ["exp"] = 1767225600,
                ["CasePreserved"] = true,
            }),
            TestContext.Current.CancellationToken);

        var payload = ParseSegment(token.Value.Split('.')[1]);
        payload.GetProperty("sub").GetString().Should().Be("alice");
        payload.GetProperty("aud").EnumerateArray().Select(e => e.GetString()).Should().Equal("api-one", "api-two");
        payload.GetProperty("exp").GetInt64().Should().Be(1767225600);
        payload.GetProperty("CasePreserved").GetBoolean().Should().BeTrue("claim names must not be rewritten by a naming policy");
    }

    [Theory]
    [InlineData(TokenKind.AccessToken, "at+jwt")]
    [InlineData(TokenKind.IdToken, "JWT")]
    public async Task IssueAsync_sets_the_typ_header_for_the_kind_being_issued(TokenKind kind, string expectedTyp)
    {
        using var rsa = RSA.Create(2048);
        var (issuer, _) = await CreateIssuerAsync(rsa);

        TokenIssuanceContext context = kind == TokenKind.IdToken
            ? new IdTokenIssuanceContext(Client, new IssuedToken("access", TokenKind.AccessToken))
            : new AccessTokenIssuanceContext(Client);

        var token = await issuer.IssueAsync(
            context,
            new TokenPayload(new Dictionary<string, object?>()),
            TestContext.Current.CancellationToken);

        ParseSegment(token.Value.Split('.')[0]).GetProperty("typ").GetString().Should().Be(expectedTyp);
        token.Kind.Should().Be(kind);
    }

    // ── Key resolution discipline ────────────────────────────────────────────────────────────────

    [Fact]
    public async Task IssueAsync_resolves_the_key_exactly_once_per_token()
    {
        var (issuer, signer) = CreateCountingIssuer();

        await issuer.IssueAsync(
            new AccessTokenIssuanceContext(Client),
            new TokenPayload(new Dictionary<string, object?> { ["sub"] = "alice" }),
            TestContext.Current.CancellationToken);

        signer.SignatureCount.Should().Be(1, "one token is one resolution — never two");
    }

    // ── Shape-agnostic contract ──────────────────────────────────────────────────────────────────

    [Fact]
    public async Task ITokenIssuer_is_implementable_by_an_opaque_issuer_with_no_JWS_types()
    {
        ITokenIssuer issuer = new OpaqueTokenIssuer();

        var token = await issuer.IssueAsync(
            new AccessTokenIssuanceContext(Client),
            new TokenPayload(new Dictionary<string, object?>()),
            TestContext.Current.CancellationToken);

        token.Value.Should().Be("opaque-handle-42");
        token.Kind.Should().Be(TokenKind.AccessToken);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public void IssuedToken_constructor_rejects_a_null_or_empty_token_value(string? value)
    {
        // An empty token on the wire is never right, and ToString()'s length-only printing
        // must never be the first thing to trip over a null.
        var act = () => new IssuedToken(value!, TokenKind.AccessToken);

        act.Should().Throw<ArgumentException>();
    }

    [Fact]
    public async Task IssueAsync_escapes_hostile_claim_names_into_exactly_one_claim()
    {
        using var rsa = RSA.Create(2048);
        var (issuer, _) = await CreateIssuerAsync(rsa);
        const string hostileName = "a\",\"admin\":\"true";

        var token = await issuer.IssueAsync(
            new AccessTokenIssuanceContext(Client),
            new TokenPayload(new Dictionary<string, object?> { [hostileName] = "x" }),
            TestContext.Current.CancellationToken);

        var payload = ParseSegment(token.Value.Split('.')[1]);
        payload.EnumerateObject().Should().ContainSingle()
            .Which.Name.Should().Be(hostileName, "the quote and comma must be escaped, never structural");
    }

    // ── Log hygiene ──────────────────────────────────────────────────────────────────────────────

    [Fact]
    public void IssuedToken_ToString_does_not_contain_the_token_value()
    {
        // The sanitizing logger redacts by placeholder name, so it cannot catch a logged
        // IssuedToken — the record itself must never print the bearer token.
        var token = new IssuedToken("eyJhbGciOiJSUzI1NiJ9.secret.payload", TokenKind.AccessToken);

        token.ToString().Should().NotContain("secret")
            .And.NotContain("eyJhbGciOiJSUzI1NiJ9")
            .And.Contain(nameof(TokenKind.AccessToken));
    }

    [Fact]
    public void TokenIssuanceContext_ToString_does_not_contain_the_access_token()
    {
        // The context reaches log lines through the sanitizing logger, which redacts by placeholder
        // name only — so the record itself must never print the bearer token it carries.
        var context = new IdTokenIssuanceContext(Client, new IssuedToken("eyJhbGciOiJSUzI1NiJ9.secret.payload", TokenKind.AccessToken));

        context.ToString().Should().NotContain("secret")
            .And.NotContain("eyJhbGciOiJSUzI1NiJ9")
            .And.Contain(nameof(TokenKind.IdToken));
        new AccessTokenIssuanceContext(Client).ToString().Should().Contain(nameof(TokenKind.AccessToken));
    }

    // ── Guards ───────────────────────────────────────────────────────────────────────────────────

    [Fact]
    public void Constructor_throws_ArgumentNullException_if_ring_is_null()
    {
        var act = () => new JwtTokenIssuer(null!);

        act.Should().Throw<ArgumentNullException>();
    }

    [Fact]
    public async Task IssueAsync_throws_ArgumentNullException_if_payload_is_null()
    {
        var (issuer, _) = CreateCountingIssuer();

        var act = () => issuer.IssueAsync(
            new AccessTokenIssuanceContext(Client), null!,
            TestContext.Current.CancellationToken);

        await act.Should().ThrowAsync<ArgumentNullException>();
    }

    // ── The ID token's binding to its access token ───────────────────────────────────────────────

    [Fact]
    public async Task An_ID_token_carries_at_hash_over_the_access_token_with_the_hash_the_key_implies()
    {
        using var rsa = RSA.Create(2048);
        var (issuer, _) = await CreateIssuerAsync(rsa);
        var accessToken = new IssuedToken("header.payload.signature", TokenKind.AccessToken);

        var idToken = await issuer.IssueAsync(
            new IdTokenIssuanceContext(Client, accessToken),
            new TokenPayload(new Dictionary<string, object?> { ["sub"] = "alice" }),
            TestContext.Current.CancellationToken);

        // OIDC Core §3.1.3.6: RS256 hashes with SHA-256; the claim is the base64url left half.
        var digest = SHA256.HashData(Encoding.ASCII.GetBytes(accessToken.Value));
        var payload = ParseSegment(idToken.Value.Split('.')[1]);
        payload.GetProperty("at_hash").GetString().Should().Be(Base64Url.EncodeToString(digest.AsSpan(0, 16)));
        payload.GetProperty("sub").GetString().Should().Be("alice", "every other claim is written verbatim");
    }

    [Fact]
    public async Task An_ID_token_signed_with_ES384_hashes_the_access_token_with_SHA_384()
    {
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP384);
        SigningKeyRing ring = new SigningKeyRing(new EcSource(ecdsa, SigningAlgorithm.ES384), new FakeTimeProvider(Epoch), TestSigningKeys.Options, new CapturingSanitizingLogger<SigningKeyRing>());
        await ring.EnsureInitializedAsync(TestContext.Current.CancellationToken);
        var issuer = new JwtTokenIssuer(ring);
        var accessToken = new IssuedToken("header.payload.signature", TokenKind.AccessToken);

        var idToken = await issuer.IssueAsync(
            new IdTokenIssuanceContext(Client, accessToken),
            new TokenPayload(new Dictionary<string, object?>()),
            TestContext.Current.CancellationToken);

        var digest = SHA384.HashData(Encoding.ASCII.GetBytes(accessToken.Value));
        ParseSegment(idToken.Value.Split('.')[1]).GetProperty("at_hash").GetString()
            .Should().Be(Base64Url.EncodeToString(digest.AsSpan(0, 24)), "the hash follows the alg of the key that signed");
    }

    [Fact]
    public async Task An_access_token_is_never_given_an_at_hash()
    {
        using var rsa = RSA.Create(2048);
        var (issuer, _) = await CreateIssuerAsync(rsa);

        var token = await issuer.IssueAsync(
            new AccessTokenIssuanceContext(Client),
            new TokenPayload(new Dictionary<string, object?> { ["sub"] = "alice" }),
            TestContext.Current.CancellationToken);

        ParseSegment(token.Value.Split('.')[1]).TryGetProperty("at_hash", out _).Should().BeFalse();
    }

    [Fact]
    public void An_ID_token_context_refuses_a_companion_that_is_not_an_access_token()
    {
        var act = () => new IdTokenIssuanceContext(Client, new IssuedToken("another-id-token", TokenKind.IdToken));

        act.Should().Throw<ArgumentException>().WithMessage("*not to a token of kind IdToken*");
    }

    [Fact]
    public void An_ID_token_context_cannot_be_built_without_an_access_token()
    {
        // The only way to an ID-token context is the IdTokenIssuanceContext constructor, and it
        // takes the access token it is bound to as a required argument — an unbound ID token is
        // unrepresentable.
        var act = () => new IdTokenIssuanceContext(Client, null!);

        act.Should().Throw<ArgumentNullException>();
    }

    [Fact]
    public async Task A_payload_already_carrying_at_hash_is_refused_before_anything_signs()
    {
        var (issuer, signer) = CreateCountingIssuer();

        var act = () => issuer.IssueAsync(
            new IdTokenIssuanceContext(Client, new IssuedToken("access", TokenKind.AccessToken)),
            new TokenPayload(new Dictionary<string, object?> { ["at_hash"] = "forged" }),
            TestContext.Current.CancellationToken);

        await act.Should().ThrowAsync<InvalidOperationException>().WithMessage("*at_hash*");
        signer.SignatureCount.Should().Be(0);
    }

    [Fact]
    public async Task An_ID_token_resolves_the_key_once()
    {
        var (issuer, signer) = CreateCountingIssuer();

        var token = await issuer.IssueAsync(
            new IdTokenIssuanceContext(Client, new IssuedToken("access", TokenKind.AccessToken)),
            new TokenPayload(new Dictionary<string, object?>()),
            TestContext.Current.CancellationToken);

        signer.SignatureCount.Should().Be(1);
        ParseSegment(token.Value.Split('.')[1]).TryGetProperty("at_hash", out _).Should().BeTrue();
    }

    [Fact]
    public async Task An_access_token_that_is_not_ASCII_is_refused_before_anything_signs()
    {
        // The hash is over ASCII octets; a value outside ASCII has no at_hash a relying party could reproduce.
        var (issuer, signer) = CreateCountingIssuer();

        var act = () => issuer.IssueAsync(
            new IdTokenIssuanceContext(Client, new IssuedToken("héader.payload.sig", TokenKind.AccessToken)),
            new TokenPayload(new Dictionary<string, object?>()),
            TestContext.Current.CancellationToken);

        await act.Should().ThrowAsync<InvalidOperationException>().WithMessage("*ASCII*");
        signer.SignatureCount.Should().Be(0);
    }

    [Fact]
    public async Task An_ID_token_escapes_hostile_claim_names_into_exactly_one_claim_beside_at_hash()
    {
        using var rsa = RSA.Create(2048);
        var (issuer, _) = await CreateIssuerAsync(rsa);
        const string hostileName = "a\",\"admin\":\"true";

        var token = await issuer.IssueAsync(
            new IdTokenIssuanceContext(Client, new IssuedToken("access", TokenKind.AccessToken)),
            new TokenPayload(new Dictionary<string, object?> { [hostileName] = "x" }),
            TestContext.Current.CancellationToken);

        var payload = ParseSegment(token.Value.Split('.')[1]);
        payload.EnumerateObject().Select(p => p.Name).Should().Equal(hostileName, "at_hash");
    }

    // ── The client's algorithm policy, enforced where the key is known ───────────────────────────

    [Fact]
    public async Task A_client_whose_allowed_algorithms_exclude_the_signing_key_is_refused_before_the_signer_is_touched()
    {
        var (issuer, signer) = CreateCountingIssuer();
        var client = new RestrictedClient(new HashSet<SigningAlgorithm> { SigningAlgorithm.ES256 });

        var act = () => issuer.IssueAsync(
            new IdTokenIssuanceContext(client, new IssuedToken("access", TokenKind.AccessToken)),
            new TokenPayload(new Dictionary<string, object?>()),
            TestContext.Current.CancellationToken);

        await act.Should().ThrowAsync<InvalidOperationException>().WithMessage("*RS256*");
        signer.SignatureCount.Should().Be(0, "the refusal is decided from the resolved key, before the signer runs");
    }

    [Fact]
    public async Task A_client_whose_allowed_algorithms_include_the_signing_key_is_issued_an_ID_token()
    {
        var (issuer, _) = CreateCountingIssuer();
        var client = new RestrictedClient(new HashSet<SigningAlgorithm> { SigningAlgorithm.RS256, SigningAlgorithm.ES256 });

        var token = await issuer.IssueAsync(
            new IdTokenIssuanceContext(client, new IssuedToken("access", TokenKind.AccessToken)),
            new TokenPayload(new Dictionary<string, object?>()),
            TestContext.Current.CancellationToken);

        token.Kind.Should().Be(TokenKind.IdToken);
    }

    [Fact]
    public async Task The_algorithm_policy_does_not_apply_to_access_tokens()
    {
        // An access token's algorithm is the resource server's concern, not the client's.
        var (issuer, _) = CreateCountingIssuer();
        var client = new RestrictedClient(new HashSet<SigningAlgorithm> { SigningAlgorithm.ES256 });

        var token = await issuer.IssueAsync(
            new AccessTokenIssuanceContext(client),
            new TokenPayload(new Dictionary<string, object?>()),
            TestContext.Current.CancellationToken);

        token.Kind.Should().Be(TokenKind.AccessToken);
    }

    // ── Helpers ──────────────────────────────────────────────────────────────────────────────────

    private static async Task<(JwtTokenIssuer Issuer, SigningKeyRing Ring)> CreateIssuerAsync(RSA rsa)
    {
        SigningKeyRing ring = new SigningKeyRing(new WorkingSource(rsa), new FakeTimeProvider(Epoch), TestSigningKeys.Options, new CapturingSanitizingLogger<SigningKeyRing>());
        await ring.EnsureInitializedAsync(TestContext.Current.CancellationToken);
        return (new JwtTokenIssuer(ring), ring);
    }

    private static JsonElement ParseSegment(string segment)
        => JsonDocument.Parse(Base64Url.DecodeFromChars(segment)).RootElement;
}
