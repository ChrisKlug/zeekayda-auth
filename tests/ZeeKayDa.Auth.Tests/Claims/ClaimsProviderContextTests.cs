using ZeeKayDa.Auth.Claims;

namespace ZeeKayDa.Auth.Tests.Claims;

public sealed class ClaimsProviderContextTests
{
    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public void A_context_without_a_subject_cannot_be_built(string? sub)
    {
        var act = () => new ClaimsProviderContext(sub!, ["openid"], new HashSet<string>(), "family");

        act.Should().Throw<ArgumentException>().Which.ParamName.Should().Be("Sub");
    }

    [Fact]
    public void The_scopes_a_provider_is_handed_are_a_read_only_copy_of_the_grants_list()
    {
        // The grant's own list is what the token's scope claim is written from. A provider must
        // not hold it: a mutable backing array could be downcast and rewritten after selection.
        var grantScopes = new List<string> { "openid", "orders.read" };
        var context = new ClaimsProviderContext("user-1", grantScopes, new HashSet<string>(), "family");

        grantScopes[1] = "orders.write";

        context.Scopes.Should().Equal("openid", "orders.read");
        ((IList<string>)context.Scopes).IsReadOnly.Should().BeTrue();
        context.Scopes.Should().NotBeOfType<string[]>();
    }

    [Fact]
    public void The_claim_types_a_provider_is_handed_are_a_read_only_copy()
    {
        var wanted = new HashSet<string> { "name" };
        var context = new ClaimsProviderContext("user-1", ["openid"], wanted, null);

        wanted.Add("email");

        context.ClaimTypes.Should().BeEquivalentTo(["name"]);
        ((ICollection<string>)context.ClaimTypes).IsReadOnly.Should().BeTrue();
    }

    [Fact]
    public void ToString_names_the_scopes_and_counts_the_claim_types_but_never_prints_the_subject()
    {
        var context = new ClaimsProviderContext("chris@example.com", ["openid", "profile"], new HashSet<string> { "name" }, "family-1");

        var text = context.ToString();

        text.Should().Contain("openid profile").And.Contain("ClaimTypes = 1").And.Contain("FamilyId = present");
        text.Should().NotContain("chris@example.com").And.NotContain("family-1");
    }
}
