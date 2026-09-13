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
    public void ToString_names_the_scopes_and_counts_the_claim_types_but_never_prints_the_subject()
    {
        var context = new ClaimsProviderContext("chris@example.com", ["openid", "profile"], new HashSet<string> { "name" }, "family-1");

        var text = context.ToString();

        text.Should().Contain("openid profile").And.Contain("ClaimTypes = 1").And.Contain("FamilyId = present");
        text.Should().NotContain("chris@example.com").And.NotContain("family-1");
    }
}
