using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.FileSystem.Tests.Fixtures;

internal static class SourceKeyListingExtensions
{
    /// <summary>
    /// Asserts the listing reports exactly one failure with <paramref name="code"/>, filed under
    /// <paramref name="id"/>, and does not also list that entry as a usable key. Returns the failure so
    /// the caller can assert on its message.
    /// </summary>
    public static ZeeKayDaConfigurationFailure ShouldReportOnly(this SourceKeyListing listing, string id, string code)
    {
        listing.Keys.Should().NotContain(k => k.Id == new SourceKeyId(id), "a failed entry is never listed");
        var reported = listing.Failures.Should().ContainSingle(f => f.Failure.Code == code).Subject;
        reported.Id.Should().Be(new SourceKeyId(id));
        return reported.Failure;
    }
}
