using System.Security.Claims;
using ZeeKayDa.Auth.AspNetCore.Interaction;

namespace ZeeKayDa.Auth.AspNetCore.Tests.Interaction;

public sealed class SessionPrincipalTests
{
    public static TheoryData<string> MalformedSubjects => new()
    {
        string.Empty,
        new string('a', 256),
        "alice@exämple.se",
        "alice smith",
        "alice\u0007",
        "alice\u007F",
    };

    [Theory]
    [MemberData(nameof(MalformedSubjects))]
    public void Build_refuses_a_subject_that_is_not_1_to_255_printable_ascii_characters(string subject)
    {
        var build = () => SessionPrincipal.Build(subject);

        build.Should().Throw<ArgumentException>().Which.ParamName.Should().Be("subject");
    }

    [Fact]
    public void Build_accepts_255_printable_ascii_characters()
    {
        var subject = string.Concat(Enumerable.Range(0, 255).Select(index => (char)('!' + index % 94)));

        var principal = SessionPrincipal.Build(subject);

        principal.FindFirstValue("sub").Should().Be(subject);
    }
}
