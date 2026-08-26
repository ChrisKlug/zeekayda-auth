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
