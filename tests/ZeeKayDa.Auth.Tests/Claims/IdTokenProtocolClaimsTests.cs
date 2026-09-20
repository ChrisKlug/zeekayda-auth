using ZeeKayDa.Auth.Authorization;
using ZeeKayDa.Auth.Claims;
using ZeeKayDa.Auth.Clients;
using ZeeKayDa.Auth.Stores;
using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.Tests.Claims;

/// <summary>
/// The set the discovery document advertises as <c>claims_supported</c> beyond what the scopes
/// unlock, held to the two things that make it safe to publish: every name in it is one an ID
/// token really carries, and every name in it is one a claims provider cannot mint.
/// </summary>
public sealed class IdTokenProtocolClaimsTests
{
    private const string Issuer = "https://auth.example.com";

    private static readonly DateTimeOffset AuthTime = new(2026, 9, 13, 11, 55, 0, TimeSpan.Zero);
    private static readonly DateTimeOffset Now = new(2026, 9, 13, 12, 0, 0, TimeSpan.Zero);

    [Fact]
    public void Every_advertised_protocol_claim_is_reserved()
    {
        // The two sets answer different questions — what the server supplies, and what a subject
        // claim may not be called — but one containment has to hold between them. A name that is
        // advertised and not reserved is one a claims provider could assert, which would make the
        // discovery document advertise a claim the subject controls.
        IdTokenProtocolClaims.Names.Should().OnlyContain(name => ReservedClaimNames.IsReserved(name));
    }

    [Fact]
    public void Every_advertised_protocol_claim_is_one_an_ID_token_carries()
    {
        // The guard against the other drift: a claim removed from the ID token but left here
        // would have the server advertising something no grant ever produces. The grant below
        // carries everything optional — a nonce, an acr and an amr — so every name must appear.
        var entry = new AuthorizationCodeEntry
        {
            ClientId = "app",
            RedirectUri = "https://app.example.com/cb",
            Pkce = new PkceChallenge("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM", CodeChallengeMethod.S256),
            Sub = "user-1",
            Scope = ["openid"],
            Nonce = "n-0S6_WzA2Mj",
            AuthTime = AuthTime,
            Acr = "urn:mace:incommon:iap:silver",
            Amr = ["pwd", "otp"],
            SsoSessionId = "session-1",
            InteractionId = "interaction-1",
            IssuedAt = Now.AddSeconds(-10),
            ExpiresAt = Now.AddSeconds(50),
        };

        var idToken = new CodeGrantTokenPayloads(
            Issuer,
            ClientRegistration.CreatePublic("app", ["https://app.example.com/cb"], [], ["openid"]),
            entry,
            Now,
            SelectedClaims.None,
            resourceAudience: null).IdToken(TimeSpan.FromHours(1)).Payload;

        idToken.Claims.Keys.Should().Contain(IdTokenProtocolClaims.Names);
    }

    [Fact]
    public void A_reserved_name_the_ID_token_never_carries_is_not_advertised()
    {
        // Reserved is the wider set by design. These are blocked so a provider cannot mint them,
        // not because the server issues them — nothing does — and publishing one would promise a
        // relying party a claim that never arrives.
        IdTokenProtocolClaims.Names.Should().NotContain(["azp", "at_hash", "c_hash", "sid", "nbf", "jti"]);
    }
}
