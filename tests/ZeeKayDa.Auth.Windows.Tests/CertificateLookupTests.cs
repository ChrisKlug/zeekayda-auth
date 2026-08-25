namespace ZeeKayDa.Auth.Windows.Tests;

/// <summary>
/// Tests for <see cref="CertificateLookup"/> and its one shipped mode,
/// <see cref="ThumbprintCertificateLookup"/>.
/// </summary>
/// <remarks>
/// Normalization is the point of this type: a thumbprint copied out of <c>certmgr</c> or the
/// Certificates MMC snap-in carries embedded spaces and an invisible leading U+200E LEFT-TO-RIGHT
/// MARK, and a lookup built from that must name the same certificate as one built from a clean
/// thumbprint.
/// </remarks>
public sealed class CertificateLookupTests
{
    private const string CleanThumbprint = "AABBCCDDEEFF00112233445566778899AABBCCDD";
    private const string MessyThumbprint = "‎aa bb cc dd ee ff 00 11 22 33 44 55 66 77 88 99 aa bb cc dd";

    private static string ThumbprintOf(CertificateLookup lookup) =>
        lookup.Should().BeOfType<ThumbprintCertificateLookup>().Subject.Thumbprint;

    [Fact]
    public void ByThumbprint_returns_a_thumbprint_lookup()
    {
        // The factory's declared return type is the base, so that adding a lookup mode later is a
        // pure addition; the mode it actually built is still observable.
        CertificateLookup.ByThumbprint(CleanThumbprint).Should().BeOfType<ThumbprintCertificateLookup>();
    }

    [Fact]
    public void ByThumbprint_keeps_an_already_clean_thumbprint_unchanged()
    {
        ThumbprintOf(CertificateLookup.ByThumbprint(CleanThumbprint)).Should().Be(CleanThumbprint);
    }

    [Fact]
    public void ByThumbprint_uppercases_a_lowercase_thumbprint()
    {
        ThumbprintOf(CertificateLookup.ByThumbprint(CleanThumbprint.ToLowerInvariant())).Should().Be(CleanThumbprint);
    }

    [Fact]
    public void ByThumbprint_strips_the_embedded_spaces_certmgr_adds()
    {
        var spacedOut = "aa bb cc dd ee ff 00 11 22 33 44 55 66 77 88 99 aa bb cc dd";

        ThumbprintOf(CertificateLookup.ByThumbprint(spacedOut)).Should().Be(CleanThumbprint);
    }

    [Fact]
    public void ByThumbprint_strips_the_invisible_left_to_right_mark_certmgr_prefixes()
    {
        var withMark = "‎" + CleanThumbprint;

        ThumbprintOf(CertificateLookup.ByThumbprint(withMark)).Should().Be(CleanThumbprint);
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
        // "XYZ-XYZ" normalizes to "", which would otherwise reach the store as a lookup for the empty
        // thumbprint and surface much later as a confusing "certificate not found: ''".
        var act = () => CertificateLookup.ByThumbprint("XYZ-XYZ");

        act.Should().Throw<ArgumentException>()
            .WithParameterName("thumbprint")
            .WithMessage("*no hex digits*");
    }

    // ── Equality ─────────────────────────────────────────────────────────────────────────────────
    // Written by hand rather than synthesized, and load-bearing: it is what the options validator
    // compares to detect two slots configured with one certificate.

    [Fact]
    public void Two_lookups_for_the_same_certificate_are_equal_however_the_thumbprint_was_written()
    {
        var fromClean = CertificateLookup.ByThumbprint(CleanThumbprint);
        var fromMessy = CertificateLookup.ByThumbprint(MessyThumbprint);

        fromMessy.Should().Be(fromClean);
        (fromMessy == fromClean).Should().BeTrue();
        (fromMessy != fromClean).Should().BeFalse();
        fromMessy.GetHashCode().Should().Be(fromClean.GetHashCode());
    }

    [Fact]
    public void Lookups_for_different_certificates_are_not_equal()
    {
        var first = CertificateLookup.ByThumbprint(CleanThumbprint);
        var second = CertificateLookup.ByThumbprint("1111111111111111111111111111111111111111");

        first.Should().NotBe(second);
        (first == second).Should().BeFalse();
        (first != second).Should().BeTrue();
    }

    [Fact]
    public void A_lookup_is_never_equal_to_null_or_to_an_unrelated_object()
    {
        var lookup = CertificateLookup.ByThumbprint(CleanThumbprint);
        CertificateLookup? nothing = null;

        lookup.Equals(nothing).Should().BeFalse();
        lookup.Equals((object?)"not a lookup").Should().BeFalse();
        (lookup == nothing).Should().BeFalse();
        (nothing == lookup).Should().BeFalse();
        (lookup != nothing).Should().BeTrue();
    }

    [Fact]
    public void Two_null_lookups_compare_equal()
    {
        // The validator compares nullable slots directly, so the null/null case is reachable there.
        CertificateLookup? left = null;
        CertificateLookup? right = null;

        (left == right).Should().BeTrue();
        (left != right).Should().BeFalse();
    }

    [Fact]
    public void The_equality_gate_cannot_be_replaced_by_a_lookup_mode()
    {
        // Symmetry across two lookup modes is structural, not a convention each mode has to honour:
        // the null check and the exact-type check live on the base and cannot be overridden, and a
        // mode supplies only EqualsCore, which the base calls once both have passed. A second mode
        // cannot be built here to demonstrate it directly — EqualsCore is private protected, so even
        // this assembly's InternalsVisibleTo grant cannot derive from CertificateLookup — so the
        // invariant is pinned on the metadata instead.
        var equals = typeof(CertificateLookup).GetMethod(nameof(CertificateLookup.Equals), [typeof(CertificateLookup)])!;

        equals.IsFinal.Should().BeTrue("a lookup mode must not be able to override the null and type checks");

        var equalsCore = typeof(CertificateLookup)
            .GetMethod("EqualsCore", System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.NonPublic)!;

        equalsCore.IsAbstract.Should().BeTrue("every lookup mode must supply its own comparison");
        equalsCore.IsFamilyAndAssembly.Should().BeTrue(
            "private protected keeps the hierarchy closed to this assembly, matching the constructor");
    }

    [Fact]
    public void ToString_names_the_thumbprint_for_diagnostics()
    {
        CertificateLookup.ByThumbprint(CleanThumbprint).ToString().Should().Contain(CleanThumbprint);
    }
}
