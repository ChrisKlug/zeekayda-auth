namespace ZeeKayDa.Auth.Tests.Exceptions;

public sealed class ZeeKayDaExceptionHierarchyTests
{
    // ── ZeeKayDaConfigurationException ───────────────────────────────────────────────────────────

    [Fact]
    public void ZeeKayDaConfigurationException_Message_contains_count_for_multiple_failures()
    {
        var ex = new ZeeKayDaConfigurationException(
            new ZeeKayDaConfigurationFailure("code.a", "message a"),
            new ZeeKayDaConfigurationFailure("code.b", "message b"));

        ex.Message.Should().Be(
            "2 configuration error(s):\n  [code.a] message a\n  [code.b] message b");
    }

    // The non-empty invariant is what lets StartupVerificationHostedService treat an absorbed
    // ZeeKayDaConfigurationException as always contributing at least one failure; a zero-failure
    // instance would let a failed startup check pass silently. Locked on every constructor
    // overload through which an empty failure set is expressible.

    [Fact]
    public void ZeeKayDaConfigurationException_throws_when_constructed_with_zero_failures()
    {
        Action act = () => throw new ZeeKayDaConfigurationException();

        act.Should().Throw<ArgumentException>()
            .WithParameterName("failures");
    }

    [Fact]
    public void ZeeKayDaConfigurationException_list_overload_throws_when_failures_is_empty()
    {
        Action act = () => throw new ZeeKayDaConfigurationException(
            Array.Empty<ZeeKayDaConfigurationFailure>(), new InvalidOperationException("root cause"));

        act.Should().Throw<ArgumentException>()
            .WithParameterName("failures");
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
}
