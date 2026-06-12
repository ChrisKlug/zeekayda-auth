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
    public void ZeeKayDaConfigurationException_SingleFailureCtor_SetsMessage()
    {
        var ex = new ZeeKayDaConfigurationException(
            new ZeeKayDaConfigurationFailure("test.code", "msg"));

        ex.Message.Should().Be("1 configuration error(s):\n  [test.code] msg");
    }

    [Fact]
    public void ZeeKayDaConfigurationException_SingleFailureCtor_SetsAggregatedFailures()
    {
        var failure = new ZeeKayDaConfigurationFailure("test.code", "msg");

        var ex = new ZeeKayDaConfigurationException(failure);

        ex.AggregatedFailures.Should().ContainSingle()
            .Which.Should().Be(failure);
    }

    [Fact]
    public void ZeeKayDaConfigurationException_MultipleFailures_SetsMessage()
    {
        var ex = new ZeeKayDaConfigurationException(
            new ZeeKayDaConfigurationFailure("code.a", "msg a"),
            new ZeeKayDaConfigurationFailure("code.b", "msg b"));

        ex.Message.Should().Be(
            "2 configuration error(s):\n  [code.a] msg a\n  [code.b] msg b");
    }

    [Fact]
    public void ZeeKayDaInteractionException_SingleArgCtor_SetsMessage()
    {
        var ex = new ZeeKayDaInteractionException("msg");

        ex.Message.Should().Be("msg");
    }

    [Fact]
    public void ZeeKayDaInteractionException_TwoArgCtor_SetsMessageAndInnerException()
    {
        var inner = new Exception("inner");

        var ex = new ZeeKayDaInteractionException("outer", inner);

        ex.Message.Should().Be("outer");
        ex.InnerException.Should().BeSameAs(inner);
    }

    [Fact]
    public void ZeeKayDaConfigurationException_IsAssignableToZeeKayDaException()
    {
        new ZeeKayDaConfigurationException(
            new ZeeKayDaConfigurationFailure("test.code", "test")).Should()
            .BeAssignableTo<ZeeKayDaException>();
    }

    [Fact]
    public void ZeeKayDaInteractionException_IsAssignableToZeeKayDaException()
    {
        new ZeeKayDaInteractionException("test").Should().BeAssignableTo<ZeeKayDaException>();
    }
}
