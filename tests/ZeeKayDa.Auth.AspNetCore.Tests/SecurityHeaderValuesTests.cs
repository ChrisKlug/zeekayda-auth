using ZeeKayDa.Auth;

namespace ZeeKayDa.Auth.AspNetCore.Tests;

public sealed class SecurityHeaderValuesTests
{
    // ── ReferrerPolicy ────────────────────────────────────────────────────────────────────────────

    [Theory]
    [InlineData(ReferrerPolicy.NoReferrer, "no-referrer")]
    [InlineData(ReferrerPolicy.NoReferrerWhenDowngrade, "no-referrer-when-downgrade")]
    [InlineData(ReferrerPolicy.Origin, "origin")]
    [InlineData(ReferrerPolicy.OriginWhenCrossOrigin, "origin-when-cross-origin")]
    [InlineData(ReferrerPolicy.SameOrigin, "same-origin")]
    [InlineData(ReferrerPolicy.StrictOrigin, "strict-origin")]
    [InlineData(ReferrerPolicy.StrictOriginWhenCrossOrigin, "strict-origin-when-cross-origin")]
    [InlineData(ReferrerPolicy.UnsafeUrl, "unsafe-url")]
    public void ToHeaderValue_returns_expected_string_for_ReferrerPolicy(ReferrerPolicy policy, string expected)
        => SecurityHeaderValues.ToHeaderValue(policy).Should().Be(expected);

    [Fact]
    public void ToHeaderValue_throws_ArgumentOutOfRangeException_for_invalid_ReferrerPolicy()
    {
        var act = () => SecurityHeaderValues.ToHeaderValue((ReferrerPolicy)9999);

        act.Should().Throw<ArgumentOutOfRangeException>();
    }

    // ── CrossOriginResourcePolicy ─────────────────────────────────────────────────────────────────

    [Theory]
    [InlineData(CrossOriginResourcePolicy.SameSite, "same-site")]
    [InlineData(CrossOriginResourcePolicy.SameOrigin, "same-origin")]
    [InlineData(CrossOriginResourcePolicy.CrossOrigin, "cross-origin")]
    public void ToHeaderValue_returns_expected_string_for_CrossOriginResourcePolicy(
        CrossOriginResourcePolicy policy, string expected)
        => SecurityHeaderValues.ToHeaderValue(policy).Should().Be(expected);

    [Fact]
    public void ToHeaderValue_throws_ArgumentOutOfRangeException_for_invalid_CrossOriginResourcePolicy()
    {
        var act = () => SecurityHeaderValues.ToHeaderValue((CrossOriginResourcePolicy)9999);

        act.Should().Throw<ArgumentOutOfRangeException>();
    }
}
