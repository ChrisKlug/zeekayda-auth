using System.Buffers.Text;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Time.Testing;
using ZeeKayDa.Auth.Clients;
using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.Tests.Tokens;

/// <summary>
/// Exercises <see cref="IdTokenHintValidator"/>: a hint is accepted only when it is an ID token this
/// server issued, and every way of failing that reads the same to the caller — as no hint at all.
/// </summary>
public sealed class IdTokenHintValidatorTests
{
    private const string Issuer = "https://auth.example.com";
    private const string ClientId = "client-a";
    private const string Subject = "alice";

    private static readonly RSA CurrentKey = RSA.Create(2048);
    private static readonly RSA PreviousKey = RSA.Create(2048);
    private static readonly RSA ForeignKey = RSA.Create(2048);

    private static readonly SigningKeySet KeySet = SigningKeySetBuilder.Build(SourceKeySet.Create(
        RsaSourceKey("previous", PreviousKey),
        RsaSourceKey("current", CurrentKey),
        next: null));

    private static string CurrentKid => KeySet.SigningKey.Kid;

    private static string PreviousKid => KeySet.Published.Single(key => key != KeySet.SigningKey).Kid;

    // ── Fakes ────────────────────────────────────────────────────────────────────────────────────

    private sealed class FakeSigningKeyRing(SigningKeySet current) : ISigningKeyRing
    {
        public SigningKeySet Current => current;

        public ValueTask<SigningOutcome> SignAsync<TState>(
            TState state,
            Func<SigningContext, TState, ReadOnlyMemory<byte>> buildSigningInput,
            CancellationToken cancellationToken = default)
            => throw new NotSupportedException();

        ValueTask ISigningKeyRing.EnsureInitializedAsync(CancellationToken cancellationToken)
            => throw new NotSupportedException();

        SigningKeySet? ISigningKeyRing.CurrentOrNull => current;
    }

    private sealed class RsaSource(RSA rsa) : ISigningKeySource
    {
        public ValueTask<SourceKeySet> ReadAsync(CancellationToken cancellationToken = default)
            => new(SourceKeySet.Create(previous: null, RsaSourceKey("current", rsa), next: null));

        public ValueTask<ISigner> CreateSignerAsync(SourceKeyId id, CancellationToken cancellationToken = default)
        {
            // A copy, because LocalSigner takes ownership and the key is shared across tests.
            var copy = RSA.Create();
            copy.ImportParameters(rsa.ExportParameters(includePrivateParameters: true));
            return new ValueTask<ISigner>(new LocalSigner(SigningAlgorithm.RS256, copy));
        }
    }

    private sealed class HintClient : IClientMetadata
    {
        public string ClientId => IdTokenHintValidatorTests.ClientId;
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

    // ── Helpers ──────────────────────────────────────────────────────────────────────────────────

    private static SourceKey RsaSourceKey(string id, RSA rsa) => new(
        new SourceKeyId(id),
        SigningAlgorithm.RS256,
        PublicKeyParameters.FromRsa(rsa.ExportParameters(includePrivateParameters: false)),
        ExpiresAt: null);

    private static IdTokenHintValidator CreateValidator(SigningKeySet? keySet = null) =>
        new(new FakeSigningKeyRing(keySet ?? KeySet), Options.Create(new AuthorizationServerOptions { Issuer = Issuer }));

    private static Dictionary<string, object?> Header(string? kid = null) => new()
    {
        ["alg"] = "RS256",
        ["typ"] = "JWT",
        ["kid"] = kid ?? CurrentKid,
    };

    private static Dictionary<string, object?> Claims() => new()
    {
        ["iss"] = Issuer,
        ["sub"] = Subject,
        ["aud"] = ClientId,
        ["iat"] = 1767225600L,
        ["exp"] = 1767225900L,
    };

    private static SigningKeySet EcKeySet(ECDsa ec) => SigningKeySetBuilder.Build(SourceKeySet.Create(
        previous: null,
        new SourceKey(
            new SourceKeyId("current"),
            SigningAlgorithm.ES256,
            PublicKeyParameters.FromEc(ec.ExportParameters(includePrivateParameters: false)),
            ExpiresAt: null),
        next: null));

    /// <summary>Signs exactly the header and payload given, RS256 with the current key unless told otherwise.</summary>
    private static string Sign(
        IDictionary<string, object?> header, object claims, Func<byte[], byte[]>? signer = null)
    {
        var signingInput = $"{Segment(header)}.{Segment(claims)}";
        var signature = (signer ?? SignWithCurrentKey)(Encoding.ASCII.GetBytes(signingInput));
        return $"{signingInput}.{Base64Url.EncodeToString(signature)}";
    }

    private static byte[] SignWithCurrentKey(byte[] input) => SignRs256(CurrentKey, input);

    private static byte[] SignRs256(RSA key, byte[] input) =>
        key.SignData(input, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

    private static string Segment(object value) => Base64Url.EncodeToString(JsonSerializer.SerializeToUtf8Bytes(value));

    // ── Accepted hints ───────────────────────────────────────────────────────────────────────────

    [Fact]
    public void Validate_returns_the_client_and_subject_of_a_hint_the_server_signed()
    {
        var token = Sign(Header(), Claims());

        var hint = CreateValidator().Validate(token, clientId: null);

        hint.Should().Be(new IdTokenHint(ClientId, Subject));
    }

    [Fact]
    public async Task Validate_accepts_an_id_token_issued_by_JwtTokenIssuer()
    {
        using var ring = new StaticSigningKeyRing(new RsaSource(CurrentKey), new FakeTimeProvider());
        await ((ISigningKeyRing)ring).EnsureInitializedAsync(TestContext.Current.CancellationToken);
        var issued = await new JwtTokenIssuer(ring).IssueAsync(
            new IdTokenIssuanceContext(new HintClient(), new IssuedToken("access", TokenKind.AccessToken)),
            new TokenPayload(Claims()),
            TestContext.Current.CancellationToken);
        var validator = new IdTokenHintValidator(ring, Options.Create(new AuthorizationServerOptions { Issuer = Issuer }));

        var hint = validator.Validate(issued.Value, ClientId);

        hint.Should().Be(new IdTokenHint(ClientId, Subject));
    }

    [Fact]
    public void Validate_accepts_a_hint_whose_exp_has_passed()
    {
        var claims = Claims();
        claims["exp"] = 946684800L;
        var token = Sign(Header(), claims);

        var hint = CreateValidator().Validate(token, ClientId);

        hint.Should().NotBeNull("a relying party sends the ID token it got at sign-in, which has usually expired by logout");
    }

    [Fact]
    public void Validate_accepts_a_hint_signed_by_the_previous_published_key()
    {
        var token = Sign(Header(PreviousKid), Claims(), input => SignRs256(PreviousKey, input));

        var hint = CreateValidator().Validate(token, ClientId);

        hint.Should().Be(new IdTokenHint(ClientId, Subject));
    }

    [Fact]
    public void Validate_accepts_a_hint_signed_with_an_EC_key()
    {
        using var ec = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var keySet = EcKeySet(ec);
        var header = Header(keySet.SigningKey.Kid);
        header["alg"] = "ES256";
        var token = Sign(header, Claims(), input =>
            ec.SignData(input, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation));

        var hint = CreateValidator(keySet).Validate(token, ClientId);

        hint.Should().Be(new IdTokenHint(ClientId, Subject));
    }

    // ── Client binding ───────────────────────────────────────────────────────────────────────────

    [Fact]
    public void Validate_refuses_a_hint_whose_aud_is_not_the_client_id_sent_with_it()
    {
        var token = Sign(Header(), Claims());

        var hint = CreateValidator().Validate(token, "client-b");

        hint.Should().BeNull("a hint issued to one client must not vouch for another client's redirect");
    }

    // ── Shape ────────────────────────────────────────────────────────────────────────────────────

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("a.b")]
    [InlineData("a.b.c.d")]
    [InlineData("!!!.!!!.!!!")]
    public void Validate_refuses_a_hint_that_is_not_a_compact_JWS(string? token)
    {
        var hint = CreateValidator().Validate(token, ClientId);

        hint.Should().BeNull();
    }

    [Fact]
    public void Validate_refuses_a_hint_whose_header_is_not_a_JSON_object()
    {
        var token = $"{Segment(new[] { "JWT" })}.{Segment(Claims())}.AA";

        var hint = CreateValidator().Validate(token, ClientId);

        hint.Should().BeNull();
    }

    [Fact]
    public void Validate_refuses_a_hint_longer_than_the_size_cap_even_when_correctly_signed()
    {
        var claims = Claims();
        claims["padding"] = new string('x', IdTokenHintValidator.MaxLength);
        var token = Sign(Header(), claims);

        var hint = CreateValidator().Validate(token, ClientId);

        hint.Should().BeNull();
    }

    // ── Header ───────────────────────────────────────────────────────────────────────────────────

    [Theory]
    [InlineData("at+jwt")]
    [InlineData("jwt")]
    [InlineData(null)]
    public void Validate_refuses_a_correctly_signed_hint_whose_typ_is_not_JWT(string? typ)
    {
        var header = Header();
        if (typ is null)
            header.Remove("typ");
        else
            header["typ"] = typ;
        var token = Sign(header, Claims());

        var hint = CreateValidator().Validate(token, ClientId);

        hint.Should().BeNull("an access token, or any other token, is not an ID token hint");
    }

    [Theory]
    [InlineData("none")]
    [InlineData("HS256")]
    [InlineData("RS384")]
    [InlineData("rs256")]
    public void Validate_refuses_a_correctly_signed_hint_whose_alg_is_not_the_keys_own(string algorithm)
    {
        var header = Header();
        header["alg"] = algorithm;
        var token = Sign(header, Claims());

        var hint = CreateValidator().Validate(token, ClientId);

        hint.Should().BeNull("the header must never choose how the signature is checked");
    }

    [Fact]
    public void Validate_refuses_a_correctly_signed_hint_with_a_crit_header()
    {
        var header = Header();
        header["crit"] = new[] { "exp" };
        var token = Sign(header, Claims());

        var hint = CreateValidator().Validate(token, ClientId);

        hint.Should().BeNull();
    }

    [Fact]
    public void Validate_refuses_a_correctly_signed_hint_without_a_kid()
    {
        var header = Header();
        header.Remove("kid");
        var token = Sign(header, Claims());

        var hint = CreateValidator().Validate(token, ClientId);

        hint.Should().BeNull();
    }

    // ── Signature ────────────────────────────────────────────────────────────────────────────────

    [Fact]
    public void Validate_refuses_a_hint_signed_by_a_key_the_server_does_not_publish()
    {
        var foreignKid = SigningKeySetBuilder.Build(SourceKeySet.Create(
            previous: null, RsaSourceKey("current", ForeignKey), next: null)).SigningKey.Kid;
        var token = Sign(Header(foreignKid), Claims(), input => SignRs256(ForeignKey, input));

        var hint = CreateValidator().Validate(token, ClientId);

        hint.Should().BeNull();
    }

    [Fact]
    public void Validate_refuses_a_hint_naming_a_published_kid_but_signed_by_another_key()
    {
        var token = Sign(Header(), Claims(), input => SignRs256(ForeignKey, input));

        var hint = CreateValidator().Validate(token, ClientId);

        hint.Should().BeNull();
    }

    [Theory]
    [InlineData("")]
    [InlineData("!!!")]
    [InlineData("AA")]
    public void Validate_refuses_without_throwing_a_hint_naming_a_published_kid_with_a_malformed_signature(string signature)
    {
        var token = $"{Segment(Header())}.{Segment(Claims())}.{signature}";

        var hint = CreateValidator().Validate(token, ClientId);

        hint.Should().BeNull();
    }

    [Fact]
    public void Validate_refuses_without_throwing_an_EC_hint_whose_signature_is_one_byte()
    {
        using var ec = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var keySet = EcKeySet(ec);
        var header = Header(keySet.SigningKey.Kid);
        header["alg"] = "ES256";
        var token = $"{Segment(header)}.{Segment(Claims())}.AA";

        var hint = CreateValidator(keySet).Validate(token, ClientId);

        hint.Should().BeNull("a platform that throws on a short signature must still read as no hint");
    }

    [Fact]
    public void Validate_refuses_a_hint_whose_payload_was_changed_after_signing()
    {
        var parts = Sign(Header(), Claims()).Split('.');
        var claims = Claims();
        claims["sub"] = "mallory";
        var tampered = $"{parts[0]}.{Segment(claims)}.{parts[2]}";

        var hint = CreateValidator().Validate(tampered, ClientId);

        hint.Should().BeNull();
    }

    // ── Claims ───────────────────────────────────────────────────────────────────────────────────

    [Theory]
    [InlineData("https://evil.example.com")]
    [InlineData("https://auth.example.com/")]
    [InlineData(null)]
    public void Validate_refuses_a_correctly_signed_hint_from_another_issuer(string? issuer)
    {
        var claims = Claims();
        if (issuer is null)
            claims.Remove("iss");
        else
            claims["iss"] = issuer;
        var token = Sign(Header(), claims);

        var hint = CreateValidator().Validate(token, ClientId);

        hint.Should().BeNull();
    }

    [Theory]
    [InlineData("")]
    [InlineData(null)]
    public void Validate_refuses_a_correctly_signed_hint_without_a_subject(string? subject)
    {
        var claims = Claims();
        if (subject is null)
            claims.Remove("sub");
        else
            claims["sub"] = subject;
        var token = Sign(Header(), claims);

        var hint = CreateValidator().Validate(token, ClientId);

        hint.Should().BeNull();
    }

    [Fact]
    public void Validate_refuses_a_correctly_signed_hint_whose_payload_is_not_a_JSON_object()
    {
        var token = Sign(Header(), new[] { Issuer, Subject, ClientId });

        var hint = CreateValidator().Validate(token, clientId: null);

        hint.Should().BeNull();
    }

    [Fact]
    public void Validate_refuses_a_correctly_signed_hint_whose_aud_is_empty()
    {
        var claims = Claims();
        claims["aud"] = "";
        var token = Sign(Header(), claims);

        var hint = CreateValidator().Validate(token, clientId: null);

        hint.Should().BeNull();
    }

    [Fact]
    public void Validate_refuses_a_correctly_signed_hint_whose_aud_is_an_array()
    {
        var claims = Claims();
        claims["aud"] = new[] { ClientId };
        var token = Sign(Header(), claims);

        var hint = CreateValidator().Validate(token, ClientId);

        hint.Should().BeNull("this server only ever issues a single-string aud");
    }

    [Fact]
    public void Validate_refuses_a_correctly_signed_hint_without_an_aud()
    {
        var claims = Claims();
        claims.Remove("aud");
        var token = Sign(Header(), claims);

        var hint = CreateValidator().Validate(token, clientId: null);

        hint.Should().BeNull();
    }
}
