using ZeeKayDa.Auth.AspNetCore.Endpoints;

namespace ZeeKayDa.Auth.AspNetCore.Tests.Endpoints;

public sealed class CacheControlHeaderTests
{
    [Theory]
    [InlineData(3600, "public, max-age=3600, must-revalidate")]
    [InlineData(1, "public, max-age=1, must-revalidate")]
    [InlineData(0, "no-store")]
    public void For_emits_max_age_at_one_second_or_more_and_no_store_at_zero(
        int seconds, string expected)
    {
        CacheControlHeader.For(TimeSpan.FromSeconds(seconds)).Should().Be(expected);
    }

    [Fact]
    public void For_emits_no_store_for_a_positive_sub_second_max_age()
    {
        // A sub-second TTL truncating to a cacheable max-age=0 would contradict the documented
        // "zero disables caching" contract.
        CacheControlHeader.For(TimeSpan.FromMilliseconds(999)).Should().Be("no-store");
    }
}
