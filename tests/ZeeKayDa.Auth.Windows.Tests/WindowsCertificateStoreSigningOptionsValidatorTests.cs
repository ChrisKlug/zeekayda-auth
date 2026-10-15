using Microsoft.Extensions.Options;
using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.Windows.Tests;

/// <summary>
/// Tests for <see cref="WindowsCertificateStoreSigningOptionsValidator"/>.
/// </summary>
/// <remarks>
/// There is no empty-thumbprint case here any more: <see cref="CertificateLookup.ByThumbprint"/>
/// rejects a thumbprint with no hex digits at construction, so a listed certificate always holds a
/// usable one and the validator has nothing left to check on that front. That rejection is covered
/// by <c>CertificateLookupTests</c>.
/// </remarks>
public sealed class WindowsCertificateStoreSigningOptionsValidatorTests
{
    private const string CurrentThumbprint = "AABBCCDDEEFF00112233445566778899AABBCCD";
    private const string OtherThumbprint = "1111111111111111111111111111111111111A";

    private static WindowsCertificateStoreSigningOptions ValidOptions() =>
        Options(CertificateLookup.ByThumbprint(CurrentThumbprint));

    private static WindowsCertificateStoreSigningOptions Options(params CertificateLookup?[] lookups)
    {
        var options = new WindowsCertificateStoreSigningOptions { Algorithm = SigningAlgorithm.RS256 };
        foreach (var lookup in lookups)
            options.Certificates.Add(lookup!);

        return options;
    }

    private static WindowsCertificateStoreSigningOptionsValidator Validator() => new();

    private static IReadOnlyList<ZeeKayDaConfigurationFailure> Validate(WindowsCertificateStoreSigningOptions options)
    {
        try
        {
            ((IValidateOptions<WindowsCertificateStoreSigningOptions>)Validator()).Validate(null, options);
            return [];
        }
        catch (ZeeKayDaConfigurationException exception)
        {
            return exception.AggregatedFailures;
        }
    }

    [Fact]
    public void Validate_succeeds_for_valid_options()
    {
        Validate(ValidOptions()).Should().BeEmpty();
    }

    [Fact]
    public void Validate_succeeds_with_several_different_certificates()
    {
        var options = Options(
            CertificateLookup.ByThumbprint(CurrentThumbprint),
            CertificateLookup.ByThumbprint(OtherThumbprint),
            CertificateLookup.ByThumbprint("2222222222222222222222222222222222222B"));

        Validate(options).Should().BeEmpty();
    }

    [Fact]
    public void Validate_fails_when_no_certificate_is_listed()
    {
        var failures = Validate(Options());

        failures.Should().ContainSingle(f => f.Code == "configuration.windows_certificate_store_signing.certificates.empty")
            .Which.Message.Should().Contain("at least one certificate");
    }

    [Fact]
    public void Validate_fails_when_a_listed_entry_is_null()
    {
        var options = ValidOptions();
        options.Certificates.Add(null!);

        var failures = Validate(options);

        failures.Should().ContainSingle(f => f.Code == "configuration.windows_certificate_store_signing.certificates.null_entry")
            .Which.Message.Should().Contain("Certificates[1]");
    }

    [Fact]
    public void Validate_fails_when_Algorithm_is_not_a_defined_enum_member()
    {
        var options = ValidOptions();
        options.Algorithm = (SigningAlgorithm)999;

        var failures = Validate(options);

        failures.Should().ContainSingle(f => f.Code == "configuration.windows_certificate_store_signing.algorithm.undefined_value")
            .Which.Message.Should().Contain("Algorithm");
    }

    [Fact]
    public void Validate_fails_when_the_same_certificate_is_listed_twice()
    {
        var options = Options(
            CertificateLookup.ByThumbprint(CurrentThumbprint),
            CertificateLookup.ByThumbprint(OtherThumbprint),
            CertificateLookup.ByThumbprint(CurrentThumbprint));

        var failures = Validate(options);

        failures.Should().ContainSingle(f => f.Code == "configuration.windows_certificate_store_signing.certificates.duplicate")
            .Which.Message.Should().Contain(CurrentThumbprint).And.Contain("2 times");
    }

    [Fact]
    public void Validate_detects_a_duplicate_however_the_thumbprint_was_written()
    {
        // The validator compares the entries as lookups, and lookup equality is over the normalized
        // thumbprint — so a duplicate is caught whichever way each thumbprint was pasted in.
        var options = Options(
            CertificateLookup.ByThumbprint(CurrentThumbprint),
            CertificateLookup.ByThumbprint("  aa bb cc dd ee ff 00 11 22 33 44 55 66 77 88 99 aa bb cc d  "));

        var failures = Validate(options);

        failures.Should().ContainSingle(f => f.Code == "configuration.windows_certificate_store_signing.certificates.duplicate");
    }

    [Fact]
    public void Validate_reports_every_problem_at_once()
    {
        var options = Options();
        options.Algorithm = (SigningAlgorithm)999;

        Validate(options).Should().HaveCount(2);
    }
}
