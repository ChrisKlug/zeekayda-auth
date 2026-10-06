using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.Tests.Tokens;

public sealed class SigningKeySetTests
{
    [Fact]
    public void Constructor_rejects_a_signing_key_that_is_not_among_the_published_keys()
    {
        var published = TestSigningKeys.KeySet(SigningAlgorithm.RS256).SigningKey;
        var unpublished = TestSigningKeys.KeySet(SigningAlgorithm.RS256).SigningKey;

        var act = () => new SigningKeySet(unpublished, [published], [SigningAlgorithm.RS256]);

        act.Should().Throw<ArgumentException>();
    }
}
