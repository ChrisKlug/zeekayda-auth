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
    public void ZeeKayDaConfigurationException_sets_Message_when_constructed_with_single_failure()
    {
        var ex = new ZeeKayDaConfigurationException(
            new ZeeKayDaConfigurationFailure("test.code", "msg"));

        ex.Message.Should().Be("1 configuration error(s):\n  [test.code] msg");
    }

    [Fact]
    public void ZeeKayDaConfigurationException_sets_AggregatedFailures_when_constructed_with_single_failure()
    {
        var failure = new ZeeKayDaConfigurationFailure("test.code", "msg");

        var ex = new ZeeKayDaConfigurationException(failure);

        ex.AggregatedFailures.Should().ContainSingle()
            .Which.Should().Be(failure);
    }

    [Fact]
    public void ZeeKayDaConfigurationException_sets_Message_when_constructed_with_multiple_failures()
    {
        var ex = new ZeeKayDaConfigurationException(
            new ZeeKayDaConfigurationFailure("code.a", "msg a"),
            new ZeeKayDaConfigurationFailure("code.b", "msg b"));

        ex.Message.Should().Be(
            "2 configuration error(s):\n  [code.a] msg a\n  [code.b] msg b");
    }

    [Fact]
    public void ZeeKayDaInteractionException_sets_Message_when_constructed_with_single_argument()
    {
        var ex = new ZeeKayDaInteractionException("msg");

        ex.Message.Should().Be("msg");
    }

    [Fact]
    public void ZeeKayDaInteractionException_sets_Message_and_InnerException_when_constructed_with_two_arguments()
    {
        var inner = new Exception("inner");

        var ex = new ZeeKayDaInteractionException("outer", inner);

        ex.Message.Should().Be("outer");
        ex.InnerException.Should().BeSameAs(inner);
    }

    [Fact]
    public void ZeeKayDaConfigurationException_is_assignable_to_ZeeKayDaException()
    {
        new ZeeKayDaConfigurationException(
            new ZeeKayDaConfigurationFailure("test.code", "test")).Should()
            .BeAssignableTo<ZeeKayDaException>();
    }

    [Fact]
    public void ZeeKayDaInteractionException_is_assignable_to_ZeeKayDaException()
    {
        new ZeeKayDaInteractionException("test").Should().BeAssignableTo<ZeeKayDaException>();
    }
}
