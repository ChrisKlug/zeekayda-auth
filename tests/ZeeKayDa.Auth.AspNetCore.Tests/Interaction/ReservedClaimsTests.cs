using System.Security.Claims;
using ZeeKayDa.Auth.AspNetCore.Interaction;

namespace ZeeKayDa.Auth.AspNetCore.Tests.Interaction;

/// <summary>
/// The framework's copy of a caller's principal: what it strips, and what the caller can no
/// longer reach once it is made.
/// </summary>
public sealed class ReservedClaimsTests
{
    [Fact]
    public void Strip_removes_every_reserved_claim_under_any_casing_and_keeps_the_rest()
    {
        var principal = new ClaimsPrincipal(new ClaimsIdentity(
            [new Claim("sub", "user-1"), new Claim("zkd:sid", "forged"), new Claim("ZKD:interaction", "forged"), new Claim("name", "Test User")],
            "test",
            "name",
            "role"));

        var stripped = ReservedClaims.Strip(principal);

        var identity = stripped.Identities.Single();
        identity.Claims.Select(claim => claim.Type).Should().Equal("sub", "name");
        identity.AuthenticationType.Should().Be("test");
        identity.NameClaimType.Should().Be("name");
        identity.RoleClaimType.Should().Be("role");
    }

    [Fact]
    public void Snapshot_shares_no_identity_with_the_caller_even_when_Clone_returns_the_same_instance()
    {
        var identity = new SelfCloningIdentity([new Claim("sub", "user-1")]);
        var principal = new ClaimsPrincipal(identity);

        var snapshot = ReservedClaims.Snapshot(principal);
        identity.RemoveClaim(identity.FindFirst("sub"));
        identity.AddClaim(new Claim("sub", "hijacked"));

        snapshot.Identities.Single().Should().NotBeSameAs(identity).And.BeOfType<ClaimsIdentity>();
        snapshot.FindFirstValue("sub").Should().Be("user-1");
    }

    [Fact]
    public void Snapshot_shares_no_claim_with_the_caller_even_when_the_claims_Clone_returns_the_same_instance()
    {
        // The identity constructor clones a foreign claim through Claim.Clone, which is virtual;
        // the snapshot must not depend on it, nor on the caller's properties dictionary.
        var claim = new SelfCloningClaim("sub", "user-1");
        claim.Properties["scope"] = "before";
        var principal = new ClaimsPrincipal(new ClaimsIdentity([claim], "test"));

        var snapshot = ReservedClaims.Snapshot(principal);
        claim.Properties["scope"] = "after";

        var copied = snapshot.FindFirst("sub")!;
        copied.Should().NotBeSameAs(claim).And.BeOfType<Claim>();
        copied.Value.Should().Be("user-1");
        copied.Issuer.Should().Be(claim.Issuer);
        copied.Properties["scope"].Should().Be("before");
    }

    private sealed class SelfCloningIdentity(IEnumerable<Claim> claims) : ClaimsIdentity(claims, "test")
    {
        public override ClaimsIdentity Clone() => this;
    }

    private sealed class SelfCloningClaim(string type, string value) : Claim(type, value)
    {
        public override Claim Clone() => this;

        public override Claim Clone(ClaimsIdentity? identity) => this;
    }
}
