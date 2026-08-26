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

    private static readonly IClientMetadata Client = new TestClient();

    // ── Fakes ────────────────────────────────────────────────────────────────────────────────────

    private sealed class TestClient : IClientMetadata
    {
        public string ClientId => "test-client";
        public bool IsPublic => true;
        public IReadOnlySet<string> RedirectUris => new HashSet<string>();
        public IReadOnlySet<string> PostLogoutRedirectUris => new HashSet<string>();
        public IReadOnlySet<string> AllowedScopes => new HashSet<string>();
        public IReadOnlySet<GrantType> AllowedGrantTypes => new HashSet<GrantType>();
        public IReadOnlySet<Authorization.ResponseType> AllowedResponseTypes => new HashSet<Authorization.ResponseType>();
        public IReadOnlySet<Authorization.ResponseMode> AllowedResponseModes => new HashSet<Authorization.ResponseMode>();
        public IReadOnlySet<string> AllowedTokenEndpointAuthMethods => new HashSet<string>();
        public bool EnableZkdErrorCodes => false;
    }

    private sealed class WorkingSource(RSA rsa) : ISigningKeySource
    {
        public ValueTask<SourceKeySet> ReadAsync(CancellationToken cancellationToken = default)
        {
            var current = new SourceKey(
                new SourceKeyId("current"),
                SigningAlgorithm.RS256,
                PublicKeyParameters.FromRsa(rsa.ExportParameters(includePrivateParameters: false)),
                ExpiresAt: null);
            return new ValueTask<SourceKeySet>(SourceKeySet.Create(previous: null, current, next: null));
        }

        public ValueTask<ISigner> CreateSignerAsync(SourceKeyId id, CancellationToken cancellationToken = default)
        {
            // A copy, because LocalSigner takes ownership and the test still needs the original
            // for signature verification.
            var copy = RSA.Create();
            copy.ImportParameters(rsa.ExportParameters(includePrivateParameters: true));
            return new ValueTask<ISigner>(new LocalSigner(SigningAlgorithm.RS256, copy));
        }
    }

    /// <summary>
    /// A counting ring: records how many times the key was resolved (one resolution per
    /// <c>SignAsync</c> call) and how many times the callback ran, and throws if
    /// <see cref="ISigningKeyRing.Current"/> is read at all — reading the key set outside the
    /// signing callback would be a second, unsynchronised resolution of the key.
    /// </summary>
    private sealed class CountingRing : ISigningKeyRing
    {
        private readonly SigningKeySet _keySet = TestSigningKeys.KeySet(SigningAlgorithm.RS256);

        public int SignAsyncCallCount { get; private set; }

        public int CallbackInvocationCount { get; private set; }

        public SigningKeySet Current =>
            throw new InvalidOperationException(
                "The issuer read ISigningKeyRing.Current — the key must only be observed inside " +
                "the SignAsync callback, where it is the key that produces the signature.");

        public ValueTask<SigningOutcome> SignAsync<TState>(
            TState state,
            Func<SigningContext, TState, ReadOnlyMemory<byte>> buildSigningInput,
            CancellationToken cancellationToken = default)
        {
            SignAsyncCallCount++;
            var input = buildSigningInput(new SigningContext(_keySet.SigningKey), state);
            CallbackInvocationCount++;
            return new ValueTask<SigningOutcome>(new SigningOutcome(input, new byte[] { 1, 2, 3 }, _keySet.SigningKey));
        }

        ValueTask ISigningKeyRing.EnsureInitializedAsync(CancellationToken cancellationToken) => ValueTask.CompletedTask;

        SigningKeySet? ISigningKeyRing.CurrentOrNull => _keySet;
    }

    /// <summary>
    /// The acceptance criterion's opaque test double: implements <see cref="ITokenIssuer"/> with no
    /// reference to any JWS-specific type — no ring, no key, no signing input.
    /// </summary>
    private sealed class OpaqueTokenIssuer : ITokenIssuer
    {
        public ValueTask<IssuedToken> IssueAsync(
            TokenIssuanceContext context, TokenPayload payload, CancellationToken cancellationToken = default)
            => new(new IssuedToken("opaque-handle-42", context.Kind));
    }

    // ── Compact serialisation and signature ──────────────────────────────────────────────────────

    [Fact]
    public async Task IssueAsync_produces_a_JWS_whose_signature_verifies_against_the_signing_key()
    {
        using var rsa = RSA.Create(2048);
        var (issuer, _) = await CreateIssuerAsync(rsa);

        var token = await issuer.IssueAsync(
            new TokenIssuanceContext(Client, TokenKind.AccessToken),
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
            new TokenIssuanceContext(Client, TokenKind.AccessToken),
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
            new TokenIssuanceContext(Client, TokenKind.AccessToken),
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

        var token = await issuer.IssueAsync(
            new TokenIssuanceContext(Client, kind),
            new TokenPayload(new Dictionary<string, object?>()),
            TestContext.Current.CancellationToken);

        ParseSegment(token.Value.Split('.')[0]).GetProperty("typ").GetString().Should().Be(expectedTyp);
        token.Kind.Should().Be(kind);
    }

    // ── Key resolution discipline ────────────────────────────────────────────────────────────────

    [Fact]
    public async Task IssueAsync_resolves_the_key_exactly_once_per_token()
    {
        var ring = new CountingRing();
        var issuer = new JwtTokenIssuer(ring);

        await issuer.IssueAsync(
            new TokenIssuanceContext(Client, TokenKind.AccessToken),
            new TokenPayload(new Dictionary<string, object?> { ["sub"] = "alice" }),
            TestContext.Current.CancellationToken);

        ring.SignAsyncCallCount.Should().Be(1, "one token is one resolution — never two");
        ring.CallbackInvocationCount.Should().Be(1);
        // CountingRing.Current throws, so reaching this line also proves the issuer never
        // re-resolved the key set between building the header and computing the signature.
    }

    // ── Shape-agnostic contract ──────────────────────────────────────────────────────────────────

    [Fact]
    public async Task ITokenIssuer_is_implementable_by_an_opaque_issuer_with_no_JWS_types()
    {
        ITokenIssuer issuer = new OpaqueTokenIssuer();

        var token = await issuer.IssueAsync(
            new TokenIssuanceContext(Client, TokenKind.AccessToken),
            new TokenPayload(new Dictionary<string, object?>()),
            TestContext.Current.CancellationToken);

        token.Value.Should().Be("opaque-handle-42");
        token.Kind.Should().Be(TokenKind.AccessToken);
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
        var issuer = new JwtTokenIssuer(new CountingRing());

        var act = () => issuer.IssueAsync(
            new TokenIssuanceContext(Client, TokenKind.AccessToken), null!,
            TestContext.Current.CancellationToken).AsTask();

        await act.Should().ThrowAsync<ArgumentNullException>();
    }

    [Fact]
    public async Task IssueAsync_throws_ArgumentOutOfRangeException_for_an_undefined_TokenKind()
    {
        var ring = new CountingRing();
        var issuer = new JwtTokenIssuer(ring);

        var act = () => issuer.IssueAsync(
            new TokenIssuanceContext(Client, (TokenKind)42),
            new TokenPayload(new Dictionary<string, object?>()),
            TestContext.Current.CancellationToken).AsTask();

        await act.Should().ThrowAsync<ArgumentOutOfRangeException>();
        ring.SignAsyncCallCount.Should().Be(0, "an undefined kind must be rejected before anything signs");
    }

    // ── Helpers ──────────────────────────────────────────────────────────────────────────────────

    private static async Task<(JwtTokenIssuer Issuer, ISigningKeyRing Ring)> CreateIssuerAsync(RSA rsa)
    {
        ISigningKeyRing ring = new StaticSigningKeyRing(new WorkingSource(rsa), new FakeTimeProvider(Epoch));
        await ring.EnsureInitializedAsync(TestContext.Current.CancellationToken);
        return (new JwtTokenIssuer(ring), ring);
    }

    private static JsonElement ParseSegment(string segment)
        => JsonDocument.Parse(Base64Url.DecodeFromChars(segment)).RootElement;
}
