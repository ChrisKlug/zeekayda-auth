using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.Tests.Tokens;

public sealed class SigningKeySetTests
{
    [Fact]
    public void Constructor_rejects_a_signing_key_that_is_not_among_the_published_keys()
    {
        var published = TestSigningKeys.KeySet(SigningAlgorithm.RS256).SigningKey!;
        var unpublished = TestSigningKeys.KeySet(SigningAlgorithm.RS256).SigningKey!;

        var act = () => new SigningKeySet(SigningAlgorithm.RS256, unpublished, [published]);

        act.Should().Throw<ArgumentException>();
    }

    [Fact]
    public void Constructor_rejects_a_published_key_under_another_algorithm()
    {
        var signing = TestSigningKeys.KeySet(SigningAlgorithm.RS256).SigningKey!;
        var other = TestSigningKeys.KeySet(SigningAlgorithm.ES256).SigningKey!;

        var act = () => new SigningKeySet(SigningAlgorithm.RS256, signing, [signing, other]);

        act.Should().Throw<ArgumentException>();
    }
}
