using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.Tests.Tokens;

public sealed class SourceKeyListingTests
{
    [Fact]
    public void A_listing_copies_its_lists_so_the_source_cannot_change_it_after_returning_it()
    {
        var keys = new List<SourceKey> { TestSigningKeys.SourceKey("listed", SigningAlgorithm.RS256) };
        var failures = new List<SourceKeyFailure> { Failure("broken") };
        var sut = new SourceKeyListing(keys, failures);

        keys.Add(TestSigningKeys.SourceKey("added", SigningAlgorithm.RS256));
        failures.Clear();

        sut.Keys.Select(key => key.Id.Value).Should().Equal("listed");
        sut.Failures.Select(failure => failure.Id.Value).Should().Equal("broken");
        sut.Keys.Should().NotBeOfType<List<SourceKey>>("a cast back to the source's own list would let it change the listing");
    }

    [Fact]
    public void A_listing_copies_lists_assigned_through_an_initializer_as_well()
    {
        var keys = new List<SourceKey> { TestSigningKeys.SourceKey("listed", SigningAlgorithm.RS256) };
        var sut = new SourceKeyListing([], []) { Keys = keys };

        keys.Clear();

        sut.Keys.Select(key => key.Id.Value).Should().Equal("listed");
    }

    [Fact]
    public void A_listing_rejects_null_lists()
    {
        var nullKeys = () => new SourceKeyListing(null!, []);
        var nullFailures = () => new SourceKeyListing([], null!);

        nullKeys.Should().Throw<ArgumentNullException>();
        nullFailures.Should().Throw<ArgumentNullException>();
    }

    private static SourceKeyFailure Failure(string id) =>
        new(new SourceKeyId(id), new ZeeKayDaConfigurationFailure("signing.test.broken", "broken"));
}
