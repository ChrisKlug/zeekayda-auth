using ZeeKayDa.Auth;

namespace ZeeKayDa.Auth.Tests.Exceptions;

public sealed class ZeeKayDaExceptionHierarchyTests
{
    [Fact]
    public void ZeeKayDaConfigurationException_IsAssignableToZeeKayDaException()
    {
        typeof(ZeeKayDaConfigurationException).Should().BeAssignableTo<ZeeKayDaException>();
    }

    [Fact]
    public void ZeeKayDaInteractionException_IsAssignableToZeeKayDaException()
    {
        typeof(ZeeKayDaInteractionException).Should().BeAssignableTo<ZeeKayDaException>();
    }

    [Fact]
    public void ZeeKayDaConfigurationException_CanBeCaughtAsZeeKayDaException()
    {
        Action act = () => throw new ZeeKayDaConfigurationException("test");

        act.Should().Throw<ZeeKayDaException>();
    }

    [Fact]
    public void ZeeKayDaInteractionException_CanBeCaughtAsZeeKayDaException()
    {
        Action act = () => throw new ZeeKayDaInteractionException("test");

        act.Should().Throw<ZeeKayDaException>();
    }

    [Fact]
    public void ZeeKayDaConfigurationException_PreservesMessage()
    {
        const string message = "Configuration is invalid.";

        var ex = new ZeeKayDaConfigurationException(message);

        ex.Message.Should().Be(message);
    }

    [Fact]
    public void ZeeKayDaInteractionException_PreservesMessage()
    {
        const string message = "Interaction API called in wrong state.";

        var ex = new ZeeKayDaInteractionException(message);

        ex.Message.Should().Be(message);
    }

    [Fact]
    public void ZeeKayDaConfigurationException_PreservesInnerException()
    {
        var inner = new InvalidOperationException("inner");

        var ex = new ZeeKayDaConfigurationException("outer", inner);

        ex.InnerException.Should().BeSameAs(inner);
    }

    [Fact]
    public void ZeeKayDaInteractionException_PreservesInnerException()
    {
        var inner = new InvalidOperationException("inner");

        var ex = new ZeeKayDaInteractionException("outer", inner);

        ex.InnerException.Should().BeSameAs(inner);
    }

    [Fact]
    public void ZeeKayDaException_IsAbstract()
    {
        typeof(ZeeKayDaException).IsAbstract.Should().BeTrue();
    }
}
