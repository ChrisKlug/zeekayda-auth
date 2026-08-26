using Microsoft.AspNetCore.Http;
using ZeeKayDa.Auth.AspNetCore.Endpoints;

namespace ZeeKayDa.Auth.AspNetCore.Tests.Endpoints;

public sealed class PublicMetadataHeadersTests
{
    private static readonly HashSet<string> NoOrigins = new(StringComparer.OrdinalIgnoreCase);

    [Theory]
    [InlineData(3600, "public, max-age=3600, must-revalidate")]
    [InlineData(1, "public, max-age=1, must-revalidate")]
    [InlineData(0, "no-store")]
    public void Apply_emits_max_age_at_one_second_or_more_and_no_store_at_zero(
        int seconds, string expected)
    {
        var context = new DefaultHttpContext();

        PublicMetadataHeaders.Apply(context, TimeSpan.FromSeconds(seconds), NoOrigins);

        context.Response.Headers.CacheControl.ToString().Should().Be(expected);
    }

    [Fact]
    public void Apply_emits_no_store_for_a_positive_sub_second_max_age()
    {
        // A sub-second TTL truncating to a cacheable max-age=0 would contradict the documented
        // "zero disables caching" contract.
        var context = new DefaultHttpContext();

        PublicMetadataHeaders.Apply(context, TimeSpan.FromMilliseconds(999), NoOrigins);

        context.Response.Headers.CacheControl.ToString().Should().Be("no-store");
    }
}
