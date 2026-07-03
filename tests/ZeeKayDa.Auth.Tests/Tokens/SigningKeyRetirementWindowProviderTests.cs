using Microsoft.Extensions.Options;
using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.Tests.Tokens;

public sealed class SigningKeyRetirementWindowProviderTests
{
    [Fact]
    public void Constructor_throws_when_options_is_null()
    {
        var act = () => new SigningKeyRetirementWindowProvider(null!);

        act.Should().Throw<ArgumentNullException>().WithParameterName("options");
    }

    [Fact]
    public void GetRetirementWindow_with_default_ClockSkewTolerance_is_one_hour_plus_default_tolerance()
    {
        var options = Options.Create(new AuthorizationServerOptions());
        var sut = new SigningKeyRetirementWindowProvider(options);

        var window = sut.GetRetirementWindow();

        window.Should().Be(TimeSpan.FromHours(1) + options.Value.ClockSkewTolerance);
    }

    [Fact]
    public void GetRetirementWindow_adds_custom_ClockSkewTolerance_to_the_one_hour_floor()
    {
        var customTolerance = TimeSpan.FromMinutes(2);
        var options = Options.Create(new AuthorizationServerOptions { ClockSkewTolerance = customTolerance });
        var sut = new SigningKeyRetirementWindowProvider(options);

        var window = sut.GetRetirementWindow();

        window.Should().Be(TimeSpan.FromHours(1) + customTolerance);
    }
}
