namespace ZeeKayDa.Auth.Tests.Logging;

public sealed class ISanitizingLoggerVisibilityTests
{
    [Fact]
    public void ISanitizingLogger_must_remain_non_public()
    {
        var type = typeof(ZeeKayDa.Auth.Logging.ISanitizingLogger<>);
        type.IsVisible.Should().BeFalse(
            "the ZEEKAYDA0002 analyzer exemption is only sound if external consumers " +
            "cannot implement ISanitizingLogger<T> to opt out of constant-template enforcement");
        type.IsPublic.Should().BeFalse();
    }
}
