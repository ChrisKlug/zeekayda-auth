using System.Buffers.Text;
using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.Extensions.Time.Testing;
using ZeeKayDa.Auth.Authorization;
using ZeeKayDa.Auth.Claims;
using ZeeKayDa.Auth.Clients;
using ZeeKayDa.Auth.Stores;
using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.Tests.Claims;

/// <summary>
/// The set the discovery document advertises as <c>claims_supported</c> beyond what the scopes
/// unlock, held to the two things that make it safe to publish: every name in it is one a signed
/// ID token really carries, and every name in it is one a claims provider cannot mint.
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
    public async Task The_advertised_protocol_claims_are_exactly_what_a_signed_ID_token_carries()
    {
        // Equality, not containment, and against the *signed* token rather than the grant's
        // payload. An ID token is assembled at more than one seam: JwtTokenIssuer writes at_hash
        // after CodeGrantTokenPayloads has built the payload, and a guard on the payload alone
        // could not see it — which is how at_hash was missing from this set to begin with.
        // Asserting equality fails in both directions: a claim added to the token and not
        // advertised, and a claim advertised that the token stopped carrying.
        using var rsa = RSA.Create(2048);
        ISigningKeyRing ring = new StaticSigningKeyRing(new SingleKeySource(rsa), new FakeTimeProvider(Now));
        await ring.EnsureInitializedAsync(TestContext.Current.CancellationToken);

        // Everything optional is present, so the token carries every name the set claims it may.
        var payload = new CodeGrantTokenPayloads(
            Issuer,
            ClientRegistration.CreatePublic("app", ["https://app.example.com/cb"], [], ["openid"]),
            Entry(),
            Now,
            SelectedClaims.None,
            resourceAudience: null).IdToken(TimeSpan.FromHours(1)).Payload;

        var idToken = await new JwtTokenIssuer(ring).IssueAsync(
            new IdTokenIssuanceContext(
                ClientRegistration.CreatePublic("app", ["https://app.example.com/cb"], [], ["openid"]),
                new IssuedToken("header.payload.signature", TokenKind.AccessToken)),
            payload,
            TestContext.Current.CancellationToken);

        var claims = JsonDocument
            .Parse(Base64Url.DecodeFromChars(idToken.Value.Split('.')[1]))
            .RootElement
            .EnumerateObject()
            .Select(property => property.Name);

        claims.Should().BeEquivalentTo(IdTokenProtocolClaims.Names);
    }

    [Fact]
    public void A_reserved_name_the_ID_token_never_carries_is_not_advertised()
    {
        // Reserved is the wider set by design. These are blocked so a provider cannot mint them,
        // not because the server issues them — nothing does — and publishing one would promise a
        // relying party a claim that never arrives. at_hash is deliberately absent from this list:
        // the issuer does write it, which is what the equality test above proves.
        IdTokenProtocolClaims.Names.Should().NotContain(["azp", "c_hash", "sid", "nbf", "jti"]);
    }

    private static AuthorizationCodeEntry Entry() => new()
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

    private sealed class SingleKeySource(RSA rsa) : ISigningKeySource
    {
        public ValueTask<SourceKeySet> ReadAsync(CancellationToken cancellationToken = default) =>
            new(SourceKeySet.Create(
                previous: null,
                new SourceKey(
                    new SourceKeyId("current"),
                    SigningAlgorithm.RS256,
                    PublicKeyParameters.FromRsa(rsa.ExportParameters(includePrivateParameters: false)),
                    ExpiresAt: null),
                next: null));

        public ValueTask<ISigner> CreateSignerAsync(SourceKeyId id, CancellationToken cancellationToken = default)
        {
            var copy = RSA.Create();
            copy.ImportParameters(rsa.ExportParameters(includePrivateParameters: true));
            return new ValueTask<ISigner>(new LocalSigner(SigningAlgorithm.RS256, copy));
        }
    }
}
