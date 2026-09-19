using System.Buffers.Text;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Time.Testing;
using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.Tests.Tokens;

/// <summary>
/// Exercises <see cref="AccessTokenValidator"/>: a token is accepted only when this server signed
/// it, addressed it to itself, and it is inside its validity window — the checks RFC 9068 §4
/// obliges a resource server to make. Every way of failing reads the same to the caller.
/// </summary>
public sealed class AccessTokenValidatorTests
{
    private const string Issuer = "https://auth.example.com";
    private const string ClientId = "client-a";
    private const string Subject = "alice";
    private const string OtherAudience = "https://orders.example.com/";

    // 2026-01-01T00:00:00Z, and a token minted to live ten minutes from it.
    private static readonly DateTimeOffset Now = DateTimeOffset.FromUnixTimeSeconds(1767225600);
    private const long IssuedAt = 1767225600L;
    private const long ExpiresAt = 1767226200L;

    private static readonly RSA CurrentKey = RSA.Create(2048);
    private static readonly RSA ForeignKey = RSA.Create(2048);

    private static readonly SigningKeySet KeySet = SigningKeySetBuilder.Build(SourceKeySet.Create(
        previous: null,
        RsaSourceKey("current", CurrentKey),
        next: null));

    private static string CurrentKid => KeySet.SigningKey.Kid;

    // ── Fakes and helpers ────────────────────────────────────────────────────────────────────────

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

    private static SourceKey RsaSourceKey(string id, RSA rsa) => new(
        new SourceKeyId(id),
        SigningAlgorithm.RS256,
        PublicKeyParameters.FromRsa(rsa.ExportParameters(includePrivateParameters: false)),
        ExpiresAt: null);

    private static AccessTokenValidator CreateValidator(TimeSpan? clockSkew = null)
    {
        var time = new FakeTimeProvider();
        time.SetUtcNow(Now);

        return new AccessTokenValidator(
            new FakeSigningKeyRing(KeySet),
            Options.Create(new AuthorizationServerOptions
            {
                Issuer = Issuer,
                ClockSkewTolerance = clockSkew ?? TimeSpan.FromSeconds(5),
            }),
            time);
    }

    private static Dictionary<string, object?> Header(string? typ = null, string? kid = null) => new()
    {
        ["alg"] = "RS256",
        ["typ"] = typ ?? "at+jwt",
        ["kid"] = kid ?? CurrentKid,
    };

    private static Dictionary<string, object?> Claims() => new()
    {
        ["iss"] = Issuer,
        ["sub"] = Subject,
        ["aud"] = Issuer,
        ["client_id"] = ClientId,
        ["iat"] = IssuedAt,
        ["exp"] = ExpiresAt,
        ["jti"] = "token-1",
        ["scope"] = "openid profile",
    };

    private static string Sign(IDictionary<string, object?> header, object claims, RSA? key = null)
    {
        var signingInput = $"{Segment(header)}.{Segment(claims)}";
        var signature = (key ?? CurrentKey).SignData(
            Encoding.ASCII.GetBytes(signingInput), HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        return $"{signingInput}.{Base64Url.EncodeToString(signature)}";
    }

    private static string Segment(object value) => Base64Url.EncodeToString(JsonSerializer.SerializeToUtf8Bytes(value));

    // ── Accepted tokens ──────────────────────────────────────────────────────────────────────────

    [Fact]
    public void Validate_returns_the_subject_client_and_scopes_of_a_token_this_server_signed()
    {
        var validated = CreateValidator().Validate(Sign(Header(), Claims()));

        validated.Should().NotBeNull();
        validated!.Subject.Should().Be(Subject);
        validated.ClientId.Should().Be(ClientId);
        validated.Scopes.Should().Equal("openid", "profile");
    }

    [Fact]
    public void Validate_accepts_the_registered_media_type_form_of_the_typ_header()
    {
        // RFC 9068 §2.1 registers application/at+jwt; a host that replaced ITokenIssuer may write it.
        var validated = CreateValidator().Validate(Sign(Header(typ: "application/at+jwt"), Claims()));

        validated.Should().NotBeNull();
    }

    [Fact]
    public void Validate_accepts_a_token_whose_audience_array_names_this_server_among_others()
    {
        var claims = Claims();
        claims["aud"] = new[] { OtherAudience, Issuer };

        CreateValidator().Validate(Sign(Header(), claims)).Should().NotBeNull(
            "RFC 7519 §4.1.3: aud is an array when a token has more than one recipient");
    }

    [Fact]
    public void Validate_accepts_a_token_with_no_scope_claim_as_carrying_none()
    {
        var claims = Claims();
        claims.Remove("scope");

        var validated = CreateValidator().Validate(Sign(Header(), claims));

        validated.Should().NotBeNull();
        validated!.Scopes.Should().BeEmpty();
    }

    [Fact]
    public void Validate_accepts_a_token_expired_within_the_clock_skew_tolerance()
    {
        var claims = Claims();
        claims["exp"] = Now.ToUnixTimeSeconds() - 3;

        CreateValidator(clockSkew: TimeSpan.FromSeconds(5)).Validate(Sign(Header(), claims))
            .Should().NotBeNull();
    }

    [Fact]
    public void Validate_accepts_a_token_whose_nbf_has_passed()
    {
        var claims = Claims();
        claims["nbf"] = IssuedAt;

        CreateValidator().Validate(Sign(Header(), claims)).Should().NotBeNull();
    }

    // ── Refused tokens ───────────────────────────────────────────────────────────────────────────

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("not-a-token")]
    [InlineData("a.b")]
    [InlineData("a.b.c.d")]
    public void Validate_refuses_anything_that_is_not_a_three_segment_token(string? token)
    {
        CreateValidator().Validate(token).Should().BeNull();
    }

    [Fact]
    public void Validate_refuses_a_token_signed_by_a_key_this_server_does_not_publish()
    {
        CreateValidator().Validate(Sign(Header(), Claims(), ForeignKey)).Should().BeNull();
    }

    [Fact]
    public void Validate_refuses_a_token_whose_payload_was_edited_after_signing()
    {
        var token = Sign(Header(), Claims());
        var segments = token.Split('.');
        var tampered = Claims();
        tampered["sub"] = "mallory";

        var forged = $"{segments[0]}.{Segment(tampered)}.{segments[2]}";

        CreateValidator().Validate(forged).Should().BeNull();
    }

    [Fact]
    public void Validate_refuses_an_id_token_presented_as_an_access_token()
    {
        // The typ header is the whole difference, and it is what stops one being spent as the other.
        CreateValidator().Validate(Sign(Header(typ: "JWT"), Claims())).Should().BeNull();
    }

    [Fact]
    public void Validate_refuses_a_token_carrying_a_crit_header()
    {
        var header = Header();
        header["crit"] = new[] { "exp" };

        CreateValidator().Validate(Sign(header, Claims())).Should().BeNull();
    }

    [Fact]
    public void Validate_refuses_a_token_issued_by_another_server()
    {
        var claims = Claims();
        claims["iss"] = "https://other.example.com";

        CreateValidator().Validate(Sign(Header(), claims)).Should().BeNull();
    }

    [Fact]
    public void Validate_refuses_a_token_whose_audience_does_not_name_this_server()
    {
        var claims = Claims();
        claims["aud"] = OtherAudience;

        CreateValidator().Validate(Sign(Header(), claims)).Should().BeNull(
            "RFC 9068 §4: a resource server rejects a token that was not addressed to it");
    }

    [Fact]
    public void Validate_refuses_a_token_whose_audience_array_does_not_name_this_server()
    {
        var claims = Claims();
        claims["aud"] = new[] { OtherAudience, "https://reports.example.com/" };

        CreateValidator().Validate(Sign(Header(), claims)).Should().BeNull();
    }

    [Fact]
    public void Validate_refuses_a_token_with_no_audience_at_all()
    {
        var claims = Claims();
        claims.Remove("aud");

        CreateValidator().Validate(Sign(Header(), claims)).Should().BeNull();
    }

    [Fact]
    public void Validate_refuses_a_token_expired_beyond_the_clock_skew_tolerance()
    {
        var claims = Claims();
        claims["exp"] = Now.ToUnixTimeSeconds() - 30;

        CreateValidator(clockSkew: TimeSpan.FromSeconds(5)).Validate(Sign(Header(), claims))
            .Should().BeNull();
    }

    [Fact]
    public void Validate_refuses_a_token_with_no_exp_rather_than_treating_it_as_eternal()
    {
        var claims = Claims();
        claims.Remove("exp");

        CreateValidator().Validate(Sign(Header(), claims)).Should().BeNull(
            "RFC 9068 §2.2 requires exp, so a token without one is malformed, not immortal");
    }

    [Theory]
    [InlineData("not-a-number")]
    [InlineData(true)]
    public void Validate_refuses_a_token_whose_exp_is_not_a_number(object exp)
    {
        var claims = Claims();
        claims["exp"] = exp;

        CreateValidator().Validate(Sign(Header(), claims)).Should().BeNull();
    }

    [Fact]
    public void Validate_refuses_a_token_that_is_not_yet_valid()
    {
        var claims = Claims();
        claims["nbf"] = Now.ToUnixTimeSeconds() + 300;

        CreateValidator().Validate(Sign(Header(), claims)).Should().BeNull();
    }

    [Theory]
    [InlineData("sub")]
    [InlineData("client_id")]
    public void Validate_refuses_a_token_missing_a_claim_the_resource_needs(string claim)
    {
        var claims = Claims();
        claims.Remove(claim);

        CreateValidator().Validate(Sign(Header(), claims)).Should().BeNull();
    }

    [Fact]
    public void Validate_refuses_a_token_whose_payload_is_not_a_JSON_object()
    {
        var signingInput = $"{Segment(Header())}.{Base64Url.EncodeToString("\"just-a-string\""u8)}";
        var signature = CurrentKey.SignData(
            Encoding.ASCII.GetBytes(signingInput), HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

        CreateValidator().Validate($"{signingInput}.{Base64Url.EncodeToString(signature)}")
            .Should().BeNull();
    }
}
