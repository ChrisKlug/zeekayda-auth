namespace ZeeKayDa.Auth.Windows.Tests;

/// <summary>
/// Tests for <see cref="CertificateLookup"/>, the value configured into each signing key slot.
/// </summary>
/// <remarks>
/// Normalization is the point of this type: a thumbprint copied out of <c>certmgr</c> or the
/// Certificates MMC snap-in carries embedded spaces and an invisible leading U+200E LEFT-TO-RIGHT
/// MARK, and a lookup built from that must find the same certificate as one built from a clean
/// thumbprint.
/// </remarks>
public sealed class CertificateLookupTests
{
    private const string CleanThumbprint = "AABBCCDDEEFF00112233445566778899AABBCCDD";

    [Fact]
    public void ByThumbprint_keeps_an_already_clean_thumbprint_unchanged()
    {
        CertificateLookup.ByThumbprint(CleanThumbprint).Thumbprint.Should().Be(CleanThumbprint);
    }

    [Fact]
    public void ByThumbprint_uppercases_a_lowercase_thumbprint()
    {
        CertificateLookup.ByThumbprint(CleanThumbprint.ToLowerInvariant()).Thumbprint.Should().Be(CleanThumbprint);
    }

    [Fact]
    public void ByThumbprint_strips_the_embedded_spaces_certmgr_adds()
    {
        var spacedOut = "aa bb cc dd ee ff 00 11 22 33 44 55 66 77 88 99 aa bb cc dd";

        CertificateLookup.ByThumbprint(spacedOut).Thumbprint.Should().Be(CleanThumbprint);
    }

    [Fact]
    public void ByThumbprint_strips_the_invisible_left_to_right_mark_certmgr_prefixes()
    {
        var withMark = "‎" + CleanThumbprint;

        CertificateLookup.ByThumbprint(withMark).Thumbprint.Should().Be(CleanThumbprint);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void ByThumbprint_throws_for_a_null_empty_or_whitespace_thumbprint(string? thumbprint)
    {
        var act = () => CertificateLookup.ByThumbprint(thumbprint!);

        act.Should().Throw<ArgumentException>().WithParameterName("thumbprint");
    }

    [Fact]
    public void ByThumbprint_throws_when_nothing_survives_normalization()
    {
        // "XYZ" normalizes to "", which would otherwise reach the store as a lookup for the empty
        // thumbprint and surface much later as a confusing "certificate not found: ''".
        var act = () => CertificateLookup.ByThumbprint("XYZ-XYZ");

        act.Should().Throw<ArgumentException>()
            .WithParameterName("thumbprint")
            .WithMessage("*no hex digits*");
    }

    [Fact]
    public void Two_lookups_for_the_same_certificate_are_equal_however_the_thumbprint_was_written()
    {
        var fromClean = CertificateLookup.ByThumbprint(CleanThumbprint);
        var fromMessy = CertificateLookup.ByThumbprint("‎aa bb cc dd ee ff 00 11 22 33 44 55 66 77 88 99 aa bb cc dd");

        fromMessy.Should().Be(fromClean, "slot duplication is detected by comparing lookups");
    }

    [Fact]
    public void Lookups_for_different_certificates_are_not_equal()
    {
        var first = CertificateLookup.ByThumbprint(CleanThumbprint);
        var second = CertificateLookup.ByThumbprint("1111111111111111111111111111111111111111");

        first.Should().NotBe(second);
    }
}
