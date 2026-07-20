using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.Windows.Tests;

public sealed class WindowsCertificateStoreSigningOptionsValidatorTests
{
    private static WindowsCertificateStoreSigningOptions ValidOptions() => new()
    {
        Thumbprint = "AABBCCDDEEFF00112233445566778899AABBCCD",
        KeyRotationCheckInterval = TimeSpan.FromMinutes(5),
        Algorithm = SigningAlgorithm.RS256,
    };

    [Fact]
    public void Validate_succeeds_for_valid_options()
    {
        var result = new WindowsCertificateStoreSigningOptionsValidator().Validate(null, ValidOptions());

        result.Succeeded.Should().BeTrue();
    }

    // The former "KeyRotationCheckInterval is null" test no longer applies: the property is now
    // non-nullable on RotatingKeySourceOptions (ADR 0011 §3.4, issue #409), so this options type
    // can no longer even represent that state.

    [Fact]
    public void Validate_fails_when_KeyRotationCheckInterval_is_below_the_one_minute_floor()
    {
        var options = ValidOptions();
        options.KeyRotationCheckInterval = TimeSpan.FromSeconds(30);

        var result = new WindowsCertificateStoreSigningOptionsValidator().Validate(null, options);

        result.Failed.Should().BeTrue();
        result.FailureMessage.Should().Contain("KeyRotationCheckInterval");
    }

    [Fact]
    public void Validate_fails_when_Thumbprint_is_empty()
    {
        var options = ValidOptions();
        options.Thumbprint = string.Empty;

        var result = new WindowsCertificateStoreSigningOptionsValidator().Validate(null, options);

        result.Failed.Should().BeTrue();
        result.FailureMessage.Should().Contain("Thumbprint");
    }

    [Fact]
    public void Validate_fails_when_Algorithm_is_not_a_defined_enum_member()
    {
        var options = ValidOptions();
        options.Algorithm = (SigningAlgorithm)999;

        var result = new WindowsCertificateStoreSigningOptionsValidator().Validate(null, options);

        result.Failed.Should().BeTrue();
        result.FailureMessage.Should().Contain("Algorithm");
    }

    [Fact]
    public void Validate_fails_when_AddCertificate_duplicates_the_primary_thumbprint()
    {
        var options = ValidOptions();
        options.AddCertificate(options.Thumbprint);

        var result = new WindowsCertificateStoreSigningOptionsValidator().Validate(null, options);

        result.Failed.Should().BeTrue();
        result.FailureMessage.Should().Contain("duplicates");
    }

    [Fact]
    public void Validate_fails_when_AddCertificate_duplicates_the_primary_thumbprint_with_different_casing_or_whitespace()
    {
        var options = ValidOptions();
        options.AddCertificate("  aa bb cc dd ee ff 00 11 22 33 44 55 66 77 88 99 aa bb cc d  ");

        var result = new WindowsCertificateStoreSigningOptionsValidator().Validate(null, options);

        result.Failed.Should().BeTrue("thumbprints are normalized before comparison");
    }

    [Fact]
    public void Validate_fails_when_two_additional_certificates_duplicate_each_other()
    {
        var options = ValidOptions();
        options.AddCertificate("1111111111111111111111111111111111111A");
        options.AddCertificate("1111111111111111111111111111111111111A");

        var result = new WindowsCertificateStoreSigningOptionsValidator().Validate(null, options);

        result.Failed.Should().BeTrue();
    }

    [Fact]
    public void Validate_fails_when_AddCertificate_thumbprint_normalizes_to_empty()
    {
        var options = ValidOptions();
        options.AddCertificate("!!!!!!!!!!!!!!!!"); // punctuation only - contains no 0-9/a-f/A-F characters at all

        var result = new WindowsCertificateStoreSigningOptionsValidator().Validate(null, options);

        result.Failed.Should().BeTrue("a thumbprint with no hex digits must be rejected at validation time, not surface later as a confusing 'certificate not found: ''' load-time failure");
    }

    [Fact]
    public void Validate_succeeds_with_distinct_additional_certificates()
    {
        var options = ValidOptions();
        options.AddCertificate("1111111111111111111111111111111111111A");
        options.AddCertificate("2222222222222222222222222222222222222B");

        var result = new WindowsCertificateStoreSigningOptionsValidator().Validate(null, options);

        result.Succeeded.Should().BeTrue();
    }
}
