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
    public void ZeeKayDaConfigurationException_SingleArgCtor_SetsMessage()
    {
        var ex = new ZeeKayDaConfigurationException("msg");

        ex.Message.Should().Be("msg");
    }

    [Fact]
    public void ZeeKayDaConfigurationException_TwoArgCtor_SetsMessageAndInnerException()
    {
        var inner = new Exception("inner");

        var ex = new ZeeKayDaConfigurationException("outer", inner);

        ex.Message.Should().Be("outer");
        ex.InnerException.Should().BeSameAs(inner);
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
        new ZeeKayDaConfigurationException("test").Should().BeAssignableTo<ZeeKayDaException>();
    }

    [Fact]
    public void ZeeKayDaInteractionException_IsAssignableToZeeKayDaException()
    {
        new ZeeKayDaInteractionException("test").Should().BeAssignableTo<ZeeKayDaException>();
    }
}
