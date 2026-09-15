using ZeeKayDa.Auth.Authorization;

namespace ZeeKayDa.Auth.Tests.Authorization;

/// <summary>
/// The server side of PKCE (RFC 7636 §4.6): the one verifier a challenge was derived from is
/// accepted, and nothing else is.
/// </summary>
public sealed class PkceVerifierTests
{
    // RFC 7636 Appendix B: the worked S256 example.
    private const string Verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    private const string Challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

    [Fact]
    public void The_verifier_a_challenge_was_derived_from_is_accepted()
    {
        PkceVerifier.Verify(Verifier, new PkceChallenge(Challenge, CodeChallengeMethod.S256))
            .Should().BeTrue("this is the RFC 7636 Appendix B vector");
    }

    [Theory]
    [InlineData("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXl", "one character differs")]
    [InlineData("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM", "the challenge itself is not the verifier")]
    [InlineData("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "an unrelated verifier")]
    public void A_verifier_the_challenge_was_not_derived_from_is_rejected(string verifier, string because)
    {
        PkceVerifier.Verify(verifier, new PkceChallenge(Challenge, CodeChallengeMethod.S256)).Should().BeFalse(because);
    }

    [Theory]
    [InlineData("e9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM", "base64url is case-sensitive")]
    [InlineData("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM=", "a padded challenge is a different string")]
    [InlineData("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-c", "a truncated challenge")]
    public void A_stored_challenge_that_is_not_exactly_the_derived_value_is_rejected(string challenge, string because)
    {
        PkceVerifier.Verify(Verifier, new PkceChallenge(challenge, CodeChallengeMethod.S256)).Should().BeFalse(because);
    }

    [Fact]
    public void A_method_the_verifier_has_no_derivation_for_fails_closed()
    {
        // The binding's constructor refuses a method outside the enum, so the only way one
        // reaches the verifier is a store that bypassed the constructor. It must not pass by
        // falling through to the S256 path, and must not throw either.
        var binding = (PkceChallenge)System.Runtime.CompilerServices.RuntimeHelpers.GetUninitializedObject(typeof(PkceChallenge));
        BackingField(nameof(PkceChallenge.Challenge)).SetValue(binding, Challenge);
        BackingField(nameof(PkceChallenge.Method)).SetValue(binding, (CodeChallengeMethod)42);

        PkceVerifier.Verify(Verifier, binding).Should().BeFalse();
    }

    private static System.Reflection.FieldInfo BackingField(string property) =>
        typeof(PkceChallenge).GetField($"<{property}>k__BackingField", System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.NonPublic)!;

    [Theory]
    [InlineData("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk", true)]
    [InlineData("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", true)]
    [InlineData("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", true)]
    [InlineData("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", false)]
    [InlineData("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", false)]
    [InlineData("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa+", false)]
    [InlineData("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/", false)]
    [InlineData("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa=", false)]
    [InlineData("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa ", false)]
    [InlineData("", false)]
    public void A_verifier_is_well_formed_only_within_RFC_7636_section_4_1(string verifier, bool wellFormed)
    {
        // 43 to 128 characters of the unreserved set: the boundaries on both sides, and each
        // character the base64 and URL alphabets would otherwise let through.
        PkceVerifier.IsWellFormed(verifier).Should().Be(wellFormed);
    }
}
