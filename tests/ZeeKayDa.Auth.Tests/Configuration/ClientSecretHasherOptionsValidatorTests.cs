using ZeeKayDa.Auth.Configuration;

namespace ZeeKayDa.Auth.Tests.Configuration;

public sealed class ClientSecretHasherOptionsValidatorTests
{
    private static IReadOnlyList<ZeeKayDaConfigurationFailure> Validate(ClientSecretHasherRegistrationOptions options)
    {
        try
        {
            new ClientSecretHasherOptionsValidator().Validate(null, options);
            return [];
        }
        catch (ZeeKayDaConfigurationException exception)
        {
            return exception.AggregatedFailures;
        }
    }

    private static ClientSecretHasherRegistrationOptions BuildOptions(
        params (Type Type, bool IsDefault)[] registrations)
    {
        var opts = new ClientSecretHasherRegistrationOptions();
        foreach (var (type, isDefault) in registrations)
            opts.Registrations.Add(new ClientSecretHasherRegistrationOptions.HasherRegistration(type, isDefault));
        return opts;
    }

    // ── Single hasher ─────────────────────────────────────────────────────────────────────────────

    [Fact]
    public void Validate_succeeds_when_one_hasher_is_registered_and_not_marked_default()
    {
        var failures = Validate(BuildOptions((typeof(HasherA), false)));

        failures.Should().BeEmpty();
    }

    [Fact]
    public void Validate_succeeds_when_one_hasher_is_registered_and_marked_default()
    {
        var failures = Validate(BuildOptions((typeof(HasherA), true)));

        failures.Should().BeEmpty();
    }

    // ── Multiple hashers ──────────────────────────────────────────────────────────────────────────

    [Fact]
    public void Validate_succeeds_when_multiple_hashers_and_exactly_one_is_default()
    {
        var failures = Validate(BuildOptions(
            (typeof(HasherA), true),
            (typeof(HasherB), false)));

        failures.Should().BeEmpty();
    }

    [Fact]
    public void Validate_fails_when_multiple_hashers_and_none_is_default()
    {
        var failures = Validate(BuildOptions(
            (typeof(HasherA), false),
            (typeof(HasherB), false)));

        failures.Should().ContainSingle(f => f.Code == "configuration.hashers.no_default")
            .Which.Message.Should().Contain("isDefault: true");
    }

    [Fact]
    public void Validate_fails_when_multiple_hashers_and_two_are_default()
    {
        var failures = Validate(BuildOptions(
            (typeof(HasherA), true),
            (typeof(HasherB), true)));

        failures.Should().ContainSingle(f => f.Code == "configuration.hashers.multiple_defaults")
            .Which.Message.Should().Contain("2");
    }

    [Fact]
    public void Validate_fails_when_three_hashers_and_two_are_default()
    {
        var failures = Validate(BuildOptions(
            (typeof(HasherA), true),
            (typeof(HasherB), false),
            (typeof(HasherC), true)));

        failures.Should().ContainSingle(f => f.Code == "configuration.hashers.multiple_defaults");
    }

    // ── Placeholder types for registration entries ────────────────────────────────────────────────

    private sealed class HasherA { }
    private sealed class HasherB { }
    private sealed class HasherC { }
}
