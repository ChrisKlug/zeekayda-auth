using System.Security.Cryptography;
using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.Tests.Tokens;

/// <summary>
/// Exercises <see cref="SigningOutcome"/>'s default-value guard: <c>Key</c> is annotated
/// non-nullable, and <see langword="default"/>(<see cref="SigningOutcome"/>) is reachable at the
/// language level.
/// </summary>
public sealed class SigningOutcomeTests
{
    [Fact]
    public void Key_throws_InvalidOperationException_on_the_default_value()
    {
        var outcome = default(SigningOutcome);

        var act = () => outcome.Key;

        act.Should().Throw<InvalidOperationException>();
    }

    [Fact]
    public void Key_returns_the_value_supplied_at_construction()
    {
        using var rsa = RSA.Create(2048);
        var key = new SigningKey(
            new SourceKeyId("current"), "kid", SigningAlgorithm.RS256, PublicKeyParameters.FromRsa(rsa.ExportParameters(false)), null);

        var outcome = new SigningOutcome(ReadOnlyMemory<byte>.Empty, ReadOnlyMemory<byte>.Empty, key);

        outcome.Key.Should().BeSameAs(key);
    }
}
