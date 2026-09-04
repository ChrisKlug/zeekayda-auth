using System.Security.Claims;
using ZeeKayDa.Auth.AspNetCore.Interaction;

namespace ZeeKayDa.Auth.AspNetCore.Tests.Interaction;

/// <summary>
/// The session subject an auto-promoted external principal gets: derived, never the upstream
/// value, and separated by provider and issuer.
/// </summary>
public sealed class ExternalSubjectTests
{
    [Fact]
    public void Derive_is_deterministic_fixed_length_and_url_safe()
    {
        var first = ExternalSubject.Derive("acme", "https://acme.example.net", "42");
        var second = ExternalSubject.Derive("acme", "https://acme.example.net", "42");

        first.Should().Be(second);
        first.Should().HaveLength(43).And.MatchRegex("^[A-Za-z0-9_-]+$");
    }

    [Theory]
    [InlineData("acme", "https://acme.example.net", "43")]
    [InlineData("acme", "https://other.example.net", "42")]
    [InlineData("globex", "https://acme.example.net", "42")]
    public void Derive_changes_when_any_part_changes(string provider, string issuer, string subject)
    {
        var baseline = ExternalSubject.Derive("acme", "https://acme.example.net", "42");

        ExternalSubject.Derive(provider, issuer, subject).Should().NotBe(baseline);
    }

    [Fact]
    public void Derive_separates_the_parts_by_length_so_boundaries_cannot_collide()
    {
        // With a separator or plain concatenation, ("ab", "c") and ("a", "bc") could hash alike.
        ExternalSubject.Derive("ab", "c", "x").Should().NotBe(ExternalSubject.Derive("a", "bc", "x"));
        ExternalSubject.Derive("a", "bc", "x").Should().NotBe(ExternalSubject.Derive("a", "b", "cx"));
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

        promoted.FindAll("sub").Select(claim => claim.Value).Should().Equal(ExternalSubject.Derive("acme", "https://acme.example.net", "42"));
        promoted.FindFirst(ClaimTypes.NameIdentifier).Should().BeNull("the upstream identifier is never carried verbatim");
        promoted.FindFirst("email")!.Value.Should().Be("user@example.net");
    }

    [Fact]
    public void ForPromotion_reads_the_name_identifier_when_there_is_no_sub()
    {
        var upstream = new ClaimsPrincipal(new ClaimsIdentity(
            [new Claim(ClaimTypes.NameIdentifier, "42", ClaimValueTypes.String, "https://acme.example.net")], "acme"));

        var promoted = ExternalSubject.ForPromotion("acme", upstream);

        promoted.FindFirst("sub")!.Value.Should().Be(ExternalSubject.Derive("acme", "https://acme.example.net", "42"));
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
