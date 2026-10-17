using System.Security.Claims;
using ZeeKayDa.Auth.AspNetCore.Interaction;

namespace ZeeKayDa.Auth.AspNetCore.Tests.Interaction;

/// <summary>
/// The session subject an auto-promoted external principal gets: derived, never the upstream
/// value, and separated by issuer.
/// </summary>
public sealed class ExternalSubjectTests
{
    [Fact]
    public void Derive_is_deterministic_fixed_length_and_url_safe()
    {
        var first = ExternalSubject.Derive("https://acme.example.net", "42");
        var second = ExternalSubject.Derive("https://acme.example.net", "42");

        first.Should().Be(second);
        first.Should().HaveLength(43).And.MatchRegex("^[A-Za-z0-9_-]+$");
    }

    [Theory]
    [InlineData("https://acme.example.net", "43")]
    [InlineData("https://other.example.net", "42")]
    [InlineData("https://Acme.example.net", "42")]
    public void Derive_changes_when_any_part_changes(string issuer, string subject)
    {
        var baseline = ExternalSubject.Derive("https://acme.example.net", "42");

        ExternalSubject.Derive(issuer, subject).Should().NotBe(baseline);
    }

    [Fact]
    public void Derive_separates_the_parts_by_length_so_boundaries_cannot_collide()
    {
        // With a separator or plain concatenation, ("ab", "c") and ("a", "bc") could hash alike.
        ExternalSubject.Derive("ab", "c").Should().NotBe(ExternalSubject.Derive("a", "bc"));
    }

    [Fact]
    public void Derive_is_the_same_under_two_registration_names_of_one_issuer()
    {
        var upstream = new ClaimsPrincipal(new ClaimsIdentity(
            [new Claim("sub", "42", ClaimValueTypes.String, "https://acme.example.net")], "upstream"));

        var throughAcme = ExternalSubject.ForPromotion("acme", upstream);
        var throughGlobex = ExternalSubject.ForPromotion("globex", upstream);

        throughGlobex.FindFirst("sub")!.Value.Should().Be(throughAcme.FindFirst("sub")!.Value)
            .And.Be(ExternalSubject.Derive("https://acme.example.net", "42"));
    }

    [Theory]
    [InlineData("", "42")]
    [InlineData("https://acme.example.net", "")]
    public void Derive_refuses_an_empty_part(string issuer, string subject)
    {
        var act = () => ExternalSubject.Derive(issuer, subject);

        act.Should().Throw<ArgumentException>();
    }

    [Fact]
    public void Identify_reads_the_issuer_and_value_of_a_subject_mapped_to_the_name_identifier()
    {
        var upstream = new ClaimsPrincipal(new ClaimsIdentity(
            [new Claim(ClaimTypes.NameIdentifier, "42", ClaimValueTypes.String, "https://acme.example.net")], "acme"));

        var identity = ExternalSubject.Identify("acme", upstream);

        identity.Subject.Should().Be("42");
        identity.Issuer.Should().Be("https://acme.example.net");
    }

    [Fact]
    public void Identify_takes_the_issuer_from_the_subject_claim_never_from_an_iss_claim()
    {
        // A separate iss claim is not bound to the subject, and a handler may carry anything in it.
        var upstream = new ClaimsPrincipal(new ClaimsIdentity(
        [
            new Claim("iss", "https://attacker.example.net", ClaimValueTypes.String, "https://acme.example.net"),
            new Claim("sub", "42", ClaimValueTypes.String, "https://acme.example.net"),
        ], "acme"));

        var identity = ExternalSubject.Identify("acme", upstream);

        identity.Issuer.Should().Be("https://acme.example.net");
    }

    [Fact]
    public void ForPromotion_replaces_the_upstream_subject_and_keeps_the_other_claims()
    {
        var upstream = new ClaimsPrincipal(new ClaimsIdentity(
        [
            new Claim("sub", "42", ClaimValueTypes.String, "https://acme.example.net"),
            new Claim(ClaimTypes.NameIdentifier, "42", ClaimValueTypes.String, "https://acme.example.net"),
            new Claim("email", "user@example.net", ClaimValueTypes.String, "https://acme.example.net"),
        ], "acme"));

        var promoted = ExternalSubject.ForPromotion("acme", upstream);

        promoted.FindAll("sub").Select(claim => claim.Value).Should().Equal(ExternalSubject.Derive("https://acme.example.net", "42"));
        promoted.FindFirst(ClaimTypes.NameIdentifier).Should().BeNull("the upstream identifier is never carried verbatim");
        promoted.FindFirst("email")!.Value.Should().Be("user@example.net");
    }

    [Fact]
    public void ForPromotion_reads_the_name_identifier_when_there_is_no_sub()
    {
        var upstream = new ClaimsPrincipal(new ClaimsIdentity(
            [new Claim(ClaimTypes.NameIdentifier, "42", ClaimValueTypes.String, "https://acme.example.net")], "acme"));

        var promoted = ExternalSubject.ForPromotion("acme", upstream);

        promoted.FindFirst("sub")!.Value.Should().Be(ExternalSubject.Derive("https://acme.example.net", "42"));
    }

    [Fact]
    public void ForPromotion_takes_the_subject_from_an_authenticated_identity_only()
    {
        // An unauthenticated auxiliary identity carrying a sub must not outrank the identity the
        // provider authenticated, whichever claim type that one uses.
        var upstream = new ClaimsPrincipal(
        [
            new ClaimsIdentity([new Claim("sub", "attacker-chosen", ClaimValueTypes.String, "https://acme.example.net")]),
            new ClaimsIdentity([new Claim(ClaimTypes.NameIdentifier, "42", ClaimValueTypes.String, "https://acme.example.net")], "acme"),
        ]);

        var promoted = ExternalSubject.ForPromotion("acme", upstream);

        promoted.FindFirst("sub")!.Value.Should().Be(ExternalSubject.Derive("https://acme.example.net", "42"));
    }

    [Fact]
    public void ForPromotion_refuses_a_subject_carried_only_by_an_unauthenticated_identity()
    {
        var upstream = new ClaimsPrincipal(
            new ClaimsIdentity([new Claim("sub", "42", ClaimValueTypes.String, "https://acme.example.net")]));

        var promote = () => ExternalSubject.ForPromotion("acme", upstream);

        promote.Should().Throw<ZeeKayDaInteractionException>().WithMessage("*authenticated identity*");
    }

    [Fact]
    public void ForPromotion_refuses_a_principal_without_a_subject()
    {
        var upstream = new ClaimsPrincipal(new ClaimsIdentity(
            [new Claim("email", "user@example.net", ClaimValueTypes.String, "https://acme.example.net")], "acme"));

        var promote = () => ExternalSubject.ForPromotion("acme", upstream);

        promote.Should().Throw<ZeeKayDaInteractionException>().WithMessage("*no subject*");
    }

    [Fact]
    public void ForPromotion_refuses_a_subject_claim_that_names_no_issuer()
    {
        var upstream = new ClaimsPrincipal(new ClaimsIdentity([new Claim("sub", "42")], "acme"));

        var promote = () => ExternalSubject.ForPromotion("acme", upstream);

        promote.Should().Throw<ZeeKayDaInteractionException>().WithMessage("*issuer*");
    }
}
