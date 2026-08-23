using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.Tests.Tokens;

/// <summary>
/// Exercises <see cref="SigningContext"/>'s default-value guard: <c>Key</c> is annotated
/// non-nullable, and <see langword="default"/>(<see cref="SigningContext"/>) is reachable at the
/// language level despite the only public constructor path being internal.
/// </summary>
public sealed class SigningContextTests
{
    [Fact]
    public void Key_throws_InvalidOperationException_on_the_default_value()
    {
        var context = default(SigningContext);

        var act = () => context.Key;

        act.Should().Throw<InvalidOperationException>();
    }
}
