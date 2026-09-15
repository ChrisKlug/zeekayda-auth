using ZeeKayDa.Auth.Authorization;
using ZeeKayDa.Auth.Claims;
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
    private static readonly TimeSpan Lifetime = TimeSpan.FromHours(1);

    private static readonly IClientMetadata Client =
        ClientRegistration.CreatePublic("app", ["https://app.example.com/cb"], [], ["openid"]);

    private static AuthorizationCodeEntry Entry(
        string? nonce = "n-0S6_WzA2Mj",
        string? acr = null,
        IReadOnlyList<string>? amr = null) => new()
        {
            ClientId = "app",
            RedirectUri = "https://app.example.com/cb",
            Pkce = new PkceChallenge("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM", CodeChallengeMethod.S256),
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

    private static CodeGrantTokenPayloads Payloads(
        AuthorizationCodeEntry? entry = null,
        SelectedClaims? subject = null,
        string? resourceAudience = null) =>
        new(Issuer, Client, entry ?? Entry(), Now, subject ?? SelectedClaims.None, resourceAudience);

    // ── The access token ──────────────────────────────────────────────────────────────────────

    [Fact]
    public void The_access_token_carries_every_claim_RFC_9068_requires_and_nothing_else()
    {
        var prepared = Payloads().AccessToken(Lifetime, jti: "token-1");

        prepared.Payload.Claims.Should().BeEquivalentTo(new Dictionary<string, object?>
        {
            ["iss"] = Issuer,
            ["sub"] = "user-1",
            ["aud"] = Issuer,
            ["client_id"] = "app",
            ["iat"] = Now.ToUnixTimeSeconds(),
            ["exp"] = Now.Add(Lifetime).ToUnixTimeSeconds(),
            ["jti"] = "token-1",
            ["scope"] = "openid profile",
            ["auth_time"] = AuthTime.ToUnixTimeSeconds(),
        });
        prepared.ExpiresAt.Should().Be(Now.Add(Lifetime));
    }

    [Fact]
    public void The_access_token_never_carries_the_nonce()
    {
        var prepared = Payloads(Entry(nonce: "n-1")).AccessToken(Lifetime, jti: "token-1");

        prepared.Payload.Claims.Should().NotContainKey("nonce", "the nonce binds the ID token to the request, not the access token");
    }

    // ── The ID token ──────────────────────────────────────────────────────────────────────────

    [Fact]
    public void The_ID_token_carries_every_claim_OIDC_Core_requires_and_the_nonce()
    {
        var prepared = Payloads().IdToken(Lifetime);

        prepared.Payload.Claims.Should().BeEquivalentTo(new Dictionary<string, object?>
        {
            ["iss"] = Issuer,
            ["sub"] = "user-1",
            ["aud"] = "app",
            ["iat"] = Now.ToUnixTimeSeconds(),
            ["exp"] = Now.Add(Lifetime).ToUnixTimeSeconds(),
            ["auth_time"] = AuthTime.ToUnixTimeSeconds(),
            ["nonce"] = "n-0S6_WzA2Mj",
        });
        prepared.ExpiresAt.Should().Be(Now.Add(Lifetime));
    }

    [Fact]
    public void The_ID_token_has_one_audience_which_is_the_client()
    {
        var prepared = Payloads().IdToken(Lifetime);

        prepared.Payload.Claims["aud"].Should().Be("app", "a single recipient is a string, not an array (RFC 7519 §4.1.3)");
    }

    [Fact]
    public void An_ID_token_for_a_grant_without_a_nonce_omits_the_claim()
    {
        var prepared = Payloads(Entry(nonce: null)).IdToken(Lifetime);

        prepared.Payload.Claims.Should().NotContainKey("nonce", "a claim is omitted, never written as null");
    }

    // ── The authentication event, on both tokens ──────────────────────────────────────────────

    [Fact]
    public void Acr_and_amr_are_written_on_both_tokens_when_the_grant_carries_them()
    {
        var payloads = Payloads(Entry(acr: "urn:mace:incommon:iap:silver", amr: ["pwd", "otp"]));

        var accessToken = payloads.AccessToken(Lifetime, jti: "token-1").Payload;
        var idToken = payloads.IdToken(Lifetime).Payload;

        foreach (var payload in new[] { accessToken, idToken })
        {
            payload.Claims["acr"].Should().Be("urn:mace:incommon:iap:silver");
            payload.Claims["amr"].Should().BeEquivalentTo(new[] { "pwd", "otp" }, options => options.WithStrictOrdering());
        }
    }

    [Fact]
    public void Acr_and_amr_are_omitted_when_the_grant_carries_none()
    {
        var payloads = Payloads(Entry(acr: null, amr: null));

        var accessToken = payloads.AccessToken(Lifetime, jti: "token-1").Payload;
        var idToken = payloads.IdToken(Lifetime).Payload;

        foreach (var payload in new[] { accessToken, idToken })
        {
            payload.Claims.Should().NotContainKey("acr");
            payload.Claims.Should().NotContainKey("amr");
        }
    }

    [Fact]
    public void An_empty_amr_list_is_omitted_rather_than_written_empty()
    {
        var prepared = Payloads(Entry(amr: [])).IdToken(Lifetime);

        prepared.Payload.Claims.Should().NotContainKey("amr");
    }

    [Fact]
    public void The_authentication_time_is_the_sign_in_the_code_was_issued_from_not_the_issuance()
    {
        var prepared = Payloads().IdToken(Lifetime);

        prepared.Payload.Claims["auth_time"].Should().Be(AuthTime.ToUnixTimeSeconds());
        prepared.Payload.Claims["auth_time"].Should().NotBe(Now.ToUnixTimeSeconds());
    }

    [Fact]
    public void Both_tokens_from_one_issuance_share_the_issued_at_instant()
    {
        var payloads = Payloads();

        var accessToken = payloads.AccessToken(TimeSpan.FromHours(1), jti: "token-1").Payload;
        var idToken = payloads.IdToken(TimeSpan.FromMinutes(5)).Payload;

        accessToken.Claims["iat"].Should().Be(idToken.Claims["iat"]);
    }

    [Fact]
    public void An_unbounded_lifetime_saturates_the_expiry_at_the_largest_representable_instant()
    {
        var prepared = Payloads().AccessToken(TimeSpan.MaxValue, jti: "token-1");

        prepared.ExpiresAt.Should().Be(DateTimeOffset.MaxValue);
        prepared.Payload.Claims["exp"].Should().Be(DateTimeOffset.MaxValue.ToUnixTimeSeconds());
    }

    // ── The access token's audience ───────────────────────────────────────────────────────────

    [Fact]
    public void Identity_scopes_alone_make_the_issuer_the_only_audience_as_a_string()
    {
        var prepared = Payloads(resourceAudience: null).AccessToken(Lifetime, jti: "token-1");

        prepared.Payload.Claims["aud"].Should().Be(Issuer, "one recipient is a string (RFC 7519 §4.1.3)");
    }

    [Fact]
    public void An_API_scope_makes_the_audience_a_two_element_array_with_the_issuer_last()
    {
        var prepared = Payloads(resourceAudience: "https://orders.example.com/").AccessToken(Lifetime, jti: "token-1");

        prepared.Payload.Claims["aud"].Should().BeEquivalentTo(new[] { "https://orders.example.com/", Issuer }, options => options.WithStrictOrdering());
    }

    [Fact]
    public void A_scope_whose_audience_is_the_issuer_names_one_recipient_not_the_same_one_twice()
    {
        var prepared = Payloads(resourceAudience: Issuer).AccessToken(Lifetime, jti: "token-1");

        prepared.Payload.Claims["aud"].Should().Be(Issuer);
    }

    [Fact]
    public void The_ID_token_audience_is_the_client_regardless_of_the_resource()
    {
        var prepared = Payloads(resourceAudience: "https://orders.example.com/").IdToken(Lifetime);

        prepared.Payload.Claims["aud"].Should().Be("app");
    }

    // ── Subject claims ────────────────────────────────────────────────────────────────────────

    [Fact]
    public void Each_token_carries_the_subject_claims_selected_for_it_and_no_others()
    {
        var subject = new SelectedClaims(
            IdToken: new Dictionary<string, ClaimValue> { ["name"] = "Chris" },
            UserInfo: new Dictionary<string, ClaimValue> { ["customer_number"] = "C-1" },
            AccessToken: new Dictionary<string, ClaimValue> { ["role"] = "admin" });

        var accessToken = Payloads(subject: subject).AccessToken(Lifetime, jti: "token-1");
        var idToken = Payloads(subject: subject).IdToken(Lifetime);

        accessToken.Payload.Claims["role"].Should().Be((ClaimValue)"admin");
        accessToken.Payload.Claims.Should().NotContainKey("name").And.NotContainKey("customer_number");
        idToken.Payload.Claims["name"].Should().Be((ClaimValue)"Chris");
        idToken.Payload.Claims.Should().NotContainKey("role").And.NotContainKey("customer_number");
    }

    [Fact]
    public void A_subject_claim_sharing_a_protocol_claims_name_fails_issuance_rather_than_overriding_the_grant()
    {
        // Selection strips reserved names before anything reaches here; if it ever did not, the
        // payload must refuse rather than let a provider's 'sub' replace the grant's.
        var subject = new SelectedClaims(
            IdToken: new Dictionary<string, ClaimValue> { ["sub"] = "attacker" },
            UserInfo: new Dictionary<string, ClaimValue>(),
            AccessToken: new Dictionary<string, ClaimValue>());

        var act = () => Payloads(subject: subject).IdToken(Lifetime);

        act.Should().Throw<ArgumentException>();
    }
}
