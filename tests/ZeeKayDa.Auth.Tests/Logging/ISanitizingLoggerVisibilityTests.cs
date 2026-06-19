namespace ZeeKayDa.Auth.Tests.Logging;

public sealed class ISanitizingLoggerVisibilityTests
{
    [Fact]
    public void ISanitizingLogger_must_remain_non_public()
    {
        var type = typeof(ZeeKayDa.Auth.Logging.ISanitizingLogger<>);
        type.IsVisible.Should().BeFalse(
            "the ZEEKAYDA0002 analyzer exemption matches ISanitizingLogger<T> by assembly identity; " +
            "making it public would allow any assembly to implement it and opt out of constant-template enforcement");
        type.IsPublic.Should().BeFalse();
    }
}
