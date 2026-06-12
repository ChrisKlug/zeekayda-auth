using Microsoft.Extensions.Options;
using ZeeKayDa.Auth.Configuration;

namespace ZeeKayDa.Auth.Tests.Configuration;

public sealed class ClientSecretHasherOptionsValidatorTests
{
    private static ValidateOptionsResult Validate(ClientSecretHasherRegistrationOptions options)
        => new ClientSecretHasherOptionsValidator().Validate(null, options);

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
        var result = Validate(BuildOptions((typeof(HasherA), false)));

        result.Succeeded.Should().BeTrue();
    }

    [Fact]
    public void Validate_succeeds_when_one_hasher_is_registered_and_marked_default()
    {
        var result = Validate(BuildOptions((typeof(HasherA), true)));

        result.Succeeded.Should().BeTrue();
    }

    // ── Multiple hashers ──────────────────────────────────────────────────────────────────────────

    [Fact]
    public void Validate_succeeds_when_multiple_hashers_and_exactly_one_is_default()
    {
        var result = Validate(BuildOptions(
            (typeof(HasherA), true),
            (typeof(HasherB), false)));

        result.Succeeded.Should().BeTrue();
    }

    [Fact]
    public void Validate_fails_when_multiple_hashers_and_none_is_default()
    {
        var result = Validate(BuildOptions(
            (typeof(HasherA), false),
            (typeof(HasherB), false)));

        result.Failed.Should().BeTrue();
        result.FailureMessage.Should().Contain("isDefault: true");
    }

    [Fact]
    public void Validate_fails_when_multiple_hashers_and_two_are_default()
    {
        var result = Validate(BuildOptions(
            (typeof(HasherA), true),
            (typeof(HasherB), true)));

        result.Failed.Should().BeTrue();
        result.FailureMessage.Should().Contain("2");
    }

    [Fact]
    public void Validate_fails_when_three_hashers_and_two_are_default()
    {
        var result = Validate(BuildOptions(
            (typeof(HasherA), true),
            (typeof(HasherB), false),
            (typeof(HasherC), true)));

        result.Failed.Should().BeTrue();
    }

    // ── Placeholder types for registration entries ────────────────────────────────────────────────

    private sealed class HasherA { }
    private sealed class HasherB { }
    private sealed class HasherC { }
}
