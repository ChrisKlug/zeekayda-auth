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
    public void Validate_OneHasher_NotMarkedDefault_Succeeds()
    {
        var result = Validate(BuildOptions((typeof(HasherA), false)));

        result.Succeeded.Should().BeTrue();
    }

    [Fact]
    public void Validate_OneHasher_MarkedDefault_Succeeds()
    {
        var result = Validate(BuildOptions((typeof(HasherA), true)));

        result.Succeeded.Should().BeTrue();
    }

    // ── Multiple hashers ──────────────────────────────────────────────────────────────────────────

    [Fact]
    public void Validate_MultipleHashers_ExactlyOneDefault_Succeeds()
    {
        var result = Validate(BuildOptions(
            (typeof(HasherA), true),
            (typeof(HasherB), false)));

        result.Succeeded.Should().BeTrue();
    }

    [Fact]
    public void Validate_MultipleHashers_NoDefault_Fails()
    {
        var result = Validate(BuildOptions(
            (typeof(HasherA), false),
            (typeof(HasherB), false)));

        result.Failed.Should().BeTrue();
        result.FailureMessage.Should().Contain("isDefault: true");
    }

    [Fact]
    public void Validate_MultipleHashers_TwoDefaults_Fails()
    {
        var result = Validate(BuildOptions(
            (typeof(HasherA), true),
            (typeof(HasherB), true)));

        result.Failed.Should().BeTrue();
        result.FailureMessage.Should().Contain("2");
    }

    [Fact]
    public void Validate_ThreeHashers_TwoDefaults_Fails()
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
