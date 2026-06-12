using ZeeKayDa.Auth;

namespace ZeeKayDa.Auth.Tests.Exceptions;

public sealed class ZeeKayDaExceptionHierarchyTests
{
    // ── Type hierarchy ────────────────────────────────────────────────────────────────────────────

    [Fact]
    public void ZeeKayDaConfigurationException_is_assignable_to_ZeeKayDaException()
    {
        typeof(ZeeKayDaConfigurationException).Should().BeAssignableTo<ZeeKayDaException>();
    }

    [Fact]
    public void ZeeKayDaInteractionException_is_assignable_to_ZeeKayDaException()
    {
        typeof(ZeeKayDaInteractionException).Should().BeAssignableTo<ZeeKayDaException>();
    }

    [Fact]
    public void ZeeKayDaException_is_abstract()
    {
        typeof(ZeeKayDaException).IsAbstract.Should().BeTrue();
    }

    // ── ZeeKayDaConfigurationException ───────────────────────────────────────────────────────────

    [Fact]
    public void ZeeKayDaConfigurationException_can_be_caught_as_ZeeKayDaException()
    {
        Action act = () => throw new ZeeKayDaConfigurationException(
            new ZeeKayDaConfigurationFailure("test.code", "test message"));

        act.Should().Throw<ZeeKayDaException>();
    }

    [Fact]
    public void ZeeKayDaConfigurationException_Message_contains_failure_count()
    {
        var ex = new ZeeKayDaConfigurationException(
            new ZeeKayDaConfigurationFailure("test.code", "test message"));

        ex.Message.Should().Be("1 configuration error(s):\n  [test.code] test message");
    }

    [Fact]
    public void ZeeKayDaConfigurationException_Message_contains_count_for_multiple_failures()
    {
        var ex = new ZeeKayDaConfigurationException(
            new ZeeKayDaConfigurationFailure("code.a", "message a"),
            new ZeeKayDaConfigurationFailure("code.b", "message b"));

        ex.Message.Should().Be(
            "2 configuration error(s):\n  [code.a] message a\n  [code.b] message b");
    }

    [Fact]
    public void ZeeKayDaConfigurationException_throws_when_constructed_with_zero_failures()
    {
        Action act = () => throw new ZeeKayDaConfigurationException();

        act.Should().Throw<ArgumentException>()
            .WithParameterName("failures");
    }

    [Fact]
    public void ZeeKayDaConfigurationException_AggregatedFailures_contains_all_passed_failures()
    {
        var f1 = new ZeeKayDaConfigurationFailure("code.a", "message a");
        var f2 = new ZeeKayDaConfigurationFailure("code.b", "message b");

        var ex = new ZeeKayDaConfigurationException(f1, f2);

        ex.AggregatedFailures.Should().HaveCount(2);
        ex.AggregatedFailures[0].Should().Be(f1);
        ex.AggregatedFailures[1].Should().Be(f2);
    }

    [Fact]
    public void ZeeKayDaConfigurationException_AggregatedFailures_is_a_defensive_copy()
    {
        var failures = new[] { new ZeeKayDaConfigurationFailure("code.a", "message a") };

        var ex = new ZeeKayDaConfigurationException(failures);

        // Mutating the original array should not affect AggregatedFailures
        failures[0] = new ZeeKayDaConfigurationFailure("code.mutated", "mutated");
        ex.AggregatedFailures[0].Code.Should().Be("code.a");
    }

    // ── ZeeKayDaInteractionException ─────────────────────────────────────────────────────────────

    [Fact]
    public void ZeeKayDaInteractionException_can_be_caught_as_ZeeKayDaException()
    {
        Action act = () => throw new ZeeKayDaInteractionException("test");

        act.Should().Throw<ZeeKayDaException>();
    }

    [Fact]
    public void ZeeKayDaInteractionException_preserves_Message()
    {
        const string message = "Interaction API called in wrong state.";

        var ex = new ZeeKayDaInteractionException(message);

        ex.Message.Should().Be(message);
    }

    [Fact]
    public void ZeeKayDaInteractionException_preserves_InnerException()
    {
        var inner = new InvalidOperationException("inner");

        var ex = new ZeeKayDaInteractionException("outer", inner);

        ex.InnerException.Should().BeSameAs(inner);
    }
}
