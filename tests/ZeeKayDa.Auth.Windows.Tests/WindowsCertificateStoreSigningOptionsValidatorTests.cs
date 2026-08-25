using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.Windows.Tests;

/// <summary>
/// Tests for <see cref="WindowsCertificateStoreSigningOptionsValidator"/>.
/// </summary>
/// <remarks>
/// There is no empty-thumbprint case here any more: <see cref="CertificateLookup.ByThumbprint"/>
/// rejects a thumbprint with no hex digits at construction, so a configured slot always holds a
/// usable one and the validator has nothing left to check on that front. That rejection is covered
/// by <c>CertificateLookupTests</c>.
/// </remarks>
public sealed class WindowsCertificateStoreSigningOptionsValidatorTests
{
    private const string CurrentThumbprint = "AABBCCDDEEFF00112233445566778899AABBCCD";
    private const string OtherThumbprint = "1111111111111111111111111111111111111A";

    private static WindowsCertificateStoreSigningOptions ValidOptions() => new()
    {
        Current = CertificateLookup.ByThumbprint(CurrentThumbprint),
        Algorithm = SigningAlgorithm.RS256,
    };

    private static WindowsCertificateStoreSigningOptionsValidator Validator() => new();

    [Fact]
    public void Validate_succeeds_for_valid_options()
    {
        var result = Validator().Validate(null, ValidOptions());

        result.Succeeded.Should().BeTrue();
    }

    [Fact]
    public void Validate_succeeds_when_only_Current_is_configured()
    {
        var options = ValidOptions();

        var result = Validator().Validate(null, options);

        result.Succeeded.Should().BeTrue("Previous and Next are independently optional");
    }

    [Fact]
    public void Validate_succeeds_with_all_three_slots_naming_different_certificates()
    {
        var options = ValidOptions();
        options.Previous = CertificateLookup.ByThumbprint(OtherThumbprint);
        options.Next = CertificateLookup.ByThumbprint("2222222222222222222222222222222222222B");

        var result = Validator().Validate(null, options);

        result.Succeeded.Should().BeTrue();
    }

    [Fact]
    public void Validate_fails_when_no_Current_is_configured()
    {
        var options = new WindowsCertificateStoreSigningOptions
        {
            Previous = CertificateLookup.ByThumbprint(OtherThumbprint),
            Algorithm = SigningAlgorithm.RS256,
        };

        var result = Validator().Validate(null, options);

        result.Failed.Should().BeTrue();
        result.FailureMessage.Should().Contain("Current");
    }

    [Fact]
    public void Validate_fails_when_Algorithm_is_not_a_defined_enum_member()
    {
        var options = ValidOptions();
        options.Algorithm = (SigningAlgorithm)999;

        var result = Validator().Validate(null, options);

        result.Failed.Should().BeTrue();
        result.FailureMessage.Should().Contain("Algorithm");
    }

    [Fact]
    public void Validate_fails_when_Previous_names_the_same_certificate_as_Current()
    {
        var options = ValidOptions();
        options.Previous = CertificateLookup.ByThumbprint(CurrentThumbprint);

        var result = Validator().Validate(null, options);

        result.Failed.Should().BeTrue();
        result.FailureMessage.Should().Contain("Previous").And.Contain("Current");
    }

    [Fact]
    public void Validate_fails_when_Next_names_the_same_certificate_as_Current()
    {
        var options = ValidOptions();
        options.Next = CertificateLookup.ByThumbprint(CurrentThumbprint);

        var result = Validator().Validate(null, options);

        result.Failed.Should().BeTrue();
        result.FailureMessage.Should().Contain("Current").And.Contain("Next");
    }

    [Fact]
    public void Validate_fails_when_Previous_and_Next_name_the_same_certificate_as_each_other()
    {
        var options = ValidOptions();
        options.Previous = CertificateLookup.ByThumbprint(OtherThumbprint);
        options.Next = CertificateLookup.ByThumbprint(OtherThumbprint);

        var result = Validator().Validate(null, options);

        result.Failed.Should().BeTrue();
        result.FailureMessage.Should().Contain("Previous").And.Contain("Next");
    }

    [Fact]
    public void Validate_detects_a_duplicate_slot_however_the_thumbprint_was_written()
    {
        // The validator compares the slots as lookups, and lookup equality is over the normalized
        // thumbprint — so a duplicate is caught whichever way each thumbprint was pasted in.
        var options = ValidOptions();
        options.Previous = CertificateLookup.ByThumbprint("  aa bb cc dd ee ff 00 11 22 33 44 55 66 77 88 99 aa bb cc d  ");

        var result = Validator().Validate(null, options);

        result.Failed.Should().BeTrue();
    }
}
