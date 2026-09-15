using ZeeKayDa.Auth.Authorization;

namespace ZeeKayDa.Auth.Tests.Authorization;

/// <summary>
/// A PKCE binding is complete or it does not exist: the challenge and its method travel as one
/// value, so nothing downstream can meet a challenge without a method or the reverse.
/// </summary>
public sealed class PkceChallengeTests
{
    private const string Challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

    [Fact]
    public void A_binding_carries_the_challenge_and_method_it_was_given()
    {
        var binding = new PkceChallenge(Challenge, CodeChallengeMethod.S256);

        binding.Challenge.Should().Be(Challenge);
        binding.Method.Should().Be(CodeChallengeMethod.S256);
        binding.Should().Be(new PkceChallenge(Challenge, CodeChallengeMethod.S256), "a binding is a value");
    }

    [Fact]
    public void A_binding_without_a_challenge_cannot_be_constructed()
    {
        var empty = () => new PkceChallenge("", CodeChallengeMethod.S256);
        var missing = () => new PkceChallenge(null!, CodeChallengeMethod.S256);

        empty.Should().Throw<ArgumentException>();
        missing.Should().Throw<ArgumentNullException>();
    }

    [Fact]
    public void A_binding_with_a_method_this_server_does_not_define_cannot_be_constructed()
    {
        var act = () => new PkceChallenge(Challenge, (CodeChallengeMethod)42);

        act.Should().Throw<ArgumentOutOfRangeException>();
    }
}
