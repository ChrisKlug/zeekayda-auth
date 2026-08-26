using ZeeKayDa.Auth;

namespace ZeeKayDa.Auth.AspNetCore.Tests.Exceptions;

/// <summary>
/// Exercises all constructor paths for the exception types defined in ZeeKayDa.Auth core.
/// These tests exist in the AspNetCore test project so that the coverage tool, which sums
/// line counts across both test assemblies, sees every line hit from both projects.
/// </summary>
public sealed class ZeeKayDaExceptionHierarchyTests
{
    [Fact]
    public void ZeeKayDaConfigurationException_sets_Message_when_constructed_with_multiple_failures()
    {
        var ex = new ZeeKayDaConfigurationException(
            new ZeeKayDaConfigurationFailure("code.a", "msg a"),
            new ZeeKayDaConfigurationFailure("code.b", "msg b"));

        ex.Message.Should().Be(
            "2 configuration error(s):\n  [code.a] msg a\n  [code.b] msg b");
    }
}
