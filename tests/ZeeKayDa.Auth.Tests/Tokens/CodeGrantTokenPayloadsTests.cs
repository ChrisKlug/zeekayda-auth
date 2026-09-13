using ZeeKayDa.Auth.Authorization;
using ZeeKayDa.Auth.Clients;
using ZeeKayDa.Auth.Stores;
using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.Tests.Tokens;

/// <summary>
/// What the tokens an authorization code becomes carry: the protocol claims RFC 9068 §2.2 and
/// OIDC Core §2 require, each taken from the grant and nothing taken from anywhere else.
/// </summary>
public sealed class CodeGrantTokenPayloadsTests
{
    private const string Issuer = "https://auth.example.com";

    private static readonly DateTimeOffset AuthTime = new(2026, 9, 13, 11, 55, 0, TimeSpan.Zero);
    private static readonly DateTimeOffset Now = new(2026, 9, 13, 12, 0, 0, TimeSpan.Zero);
    private static readonly DateTimeOffset ExpiresAt = Now.AddHours(1);

    private static readonly IClientMetadata Client =
        ClientRegistration.CreatePublic("app", ["https://app.example.com/cb"], [], ["openid"]);

    private static AuthorizationCodeEntry Entry(
        string? nonce = "n-0S6_WzA2Mj",
        string? acr = null,
        IReadOnlyList<string>? amr = null) => new()
        {
            ClientId = "app",
            RedirectUri = "https://app.example.com/cb",
            CodeChallenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
            CodeChallengeMethod = CodeChallengeMethod.S256,
            Sub = "user-1",
            Scope = ["openid", "profile"],
            Nonce = nonce,
            AuthTime = AuthTime,
            Acr = acr,
            Amr = amr,
            SsoSessionId = "session-1",
            InteractionId = "interaction-1",
            IssuedAt = Now.AddSeconds(-10),
            ExpiresAt = Now.AddSeconds(50),
        };

    // ── The access token ──────────────────────────────────────────────────────────────────────

    [Fact]
    public void The_access_token_carries_every_claim_RFC_9068_requires_and_nothing_else()
    {
        var payload = CodeGrantTokenPayloads.AccessToken(Issuer, Client, Entry(), Now, ExpiresAt, jti: "token-1");

        payload.Claims.Should().BeEquivalentTo(new Dictionary<string, object?>
        {
            ["iss"] = Issuer,
            ["sub"] = "user-1",
            ["aud"] = Issuer,
            ["client_id"] = "app",
            ["iat"] = Now.ToUnixTimeSeconds(),
            ["exp"] = ExpiresAt.ToUnixTimeSeconds(),
            ["jti"] = "token-1",
            ["scope"] = "openid profile",
            ["auth_time"] = AuthTime.ToUnixTimeSeconds(),
        });
    }

    [Fact]
    public void The_access_token_never_carries_the_nonce()
    {
        var payload = CodeGrantTokenPayloads.AccessToken(Issuer, Client, Entry(nonce: "n-1"), Now, ExpiresAt, jti: "token-1");

        payload.Claims.Should().NotContainKey("nonce", "the nonce binds the ID token to the request, not the access token");
    }

    // ── The ID token ──────────────────────────────────────────────────────────────────────────

    [Fact]
    public void The_ID_token_carries_every_claim_OIDC_Core_requires_and_the_nonce()
    {
        var payload = CodeGrantTokenPayloads.IdToken(Issuer, Client, Entry(), Now, ExpiresAt);

        payload.Claims.Should().BeEquivalentTo(new Dictionary<string, object?>
        {
            ["iss"] = Issuer,
            ["sub"] = "user-1",
            ["aud"] = "app",
            ["iat"] = Now.ToUnixTimeSeconds(),
            ["exp"] = ExpiresAt.ToUnixTimeSeconds(),
            ["auth_time"] = AuthTime.ToUnixTimeSeconds(),
            ["nonce"] = "n-0S6_WzA2Mj",
        });
    }

    [Fact]
    public void The_ID_token_has_one_audience_which_is_the_client()
    {
        var payload = CodeGrantTokenPayloads.IdToken(Issuer, Client, Entry(), Now, ExpiresAt);

        payload.Claims["aud"].Should().Be("app", "a single recipient is a string, not an array (RFC 7519 §4.1.3)");
    }

    [Fact]
    public void An_ID_token_for_a_grant_without_a_nonce_omits_the_claim()
    {
        var payload = CodeGrantTokenPayloads.IdToken(Issuer, Client, Entry(nonce: null), Now, ExpiresAt);

        payload.Claims.Should().NotContainKey("nonce", "a claim is omitted, never written as null");
    }

    // ── The authentication event, on both tokens ──────────────────────────────────────────────

    [Fact]
    public void Acr_and_amr_are_written_on_both_tokens_when_the_grant_carries_them()
    {
        var entry = Entry(acr: "urn:mace:incommon:iap:silver", amr: ["pwd", "otp"]);

        var accessToken = CodeGrantTokenPayloads.AccessToken(Issuer, Client, entry, Now, ExpiresAt, jti: "token-1");
        var idToken = CodeGrantTokenPayloads.IdToken(Issuer, Client, entry, Now, ExpiresAt);

        foreach (var payload in new[] { accessToken, idToken })
        {
            payload.Claims["acr"].Should().Be("urn:mace:incommon:iap:silver");
            payload.Claims["amr"].Should().BeEquivalentTo(new[] { "pwd", "otp" }, options => options.WithStrictOrdering());
        }
    }

    [Fact]
    public void Acr_and_amr_are_omitted_when_the_grant_carries_none()
    {
        var entry = Entry(acr: null, amr: null);

        var accessToken = CodeGrantTokenPayloads.AccessToken(Issuer, Client, entry, Now, ExpiresAt, jti: "token-1");
        var idToken = CodeGrantTokenPayloads.IdToken(Issuer, Client, entry, Now, ExpiresAt);

        foreach (var payload in new[] { accessToken, idToken })
        {
            payload.Claims.Should().NotContainKey("acr");
            payload.Claims.Should().NotContainKey("amr");
        }
    }

    [Fact]
    public void An_empty_amr_list_is_omitted_rather_than_written_empty()
    {
        var payload = CodeGrantTokenPayloads.IdToken(Issuer, Client, Entry(amr: []), Now, ExpiresAt);

        payload.Claims.Should().NotContainKey("amr");
    }

    [Fact]
    public void The_authentication_time_is_the_sign_in_the_code_was_issued_from_not_the_issuance()
    {
        var payload = CodeGrantTokenPayloads.IdToken(Issuer, Client, Entry(), Now, ExpiresAt);

        payload.Claims["auth_time"].Should().Be(AuthTime.ToUnixTimeSeconds());
        payload.Claims["auth_time"].Should().NotBe(Now.ToUnixTimeSeconds());
    }

    [Fact]
    public void A_saturated_expiry_serialises_as_the_largest_representable_instant()
    {
        var payload = CodeGrantTokenPayloads.AccessToken(Issuer, Client, Entry(), Now, DateTimeOffset.MaxValue, jti: "token-1");

        payload.Claims["exp"].Should().Be(DateTimeOffset.MaxValue.ToUnixTimeSeconds());
    }
}
